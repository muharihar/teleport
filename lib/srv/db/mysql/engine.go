/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/auth/proto"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/srv/db/session"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/siddontang/go-mysql/client"
	"github.com/siddontang/go-mysql/packet"
	"github.com/siddontang/go-mysql/server"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"
)

// Engine implements the MySQL database service that accepts client
// connections coming over reverse tunnel from the proxy and proxies
// them between the proxy and the MySQL database instance.
//
// Implements db.DatabaseEngine.
type Engine struct {
	// AuthClient is the cluster auth client.
	AuthClient *auth.Client
	// Credentials are the AWS credentials used to generate RDS auth tokens.
	Credentials *credentials.Credentials
	// RDSCACerts contains AWS RDS root certificates.
	RDSCACerts map[string][]byte
	// StreamWriter is the async audit logger.
	StreamWriter events.StreamWriter
	// OnSessionStart is called upon successful connection to the database.
	OnSessionStart func(session.Context, error) error
	// OnSessionEnd is called upon disconnection from the database.
	OnSessionEnd func(session.Context) error
	// OnQuery is called when an SQL query is executed on the connection.
	OnQuery func(session.Context, string) error
	// Clock is the clock interface.
	Clock clockwork.Clock
	// Log is used for logging.
	Log logrus.FieldLogger
}

// HandleConnection processes the connection from MySQL proxy coming
// over reverse tunnel.
//
// It handles all necessary startup actions, authorization and acts as a
// middleman between the proxy and the database intercepting and interpreting
// all messages i.e. doing protocol parsing.
func (e *Engine) HandleConnection(ctx context.Context, sessionCtx *session.Context, clientConn net.Conn) (err error) {
	err = e.checkAccess(sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	// Make server conn to get access to WriteOK method.
	proxyConn := server.Conn{
		Conn: packet.NewConn(clientConn),
	}
	// err = proxyConn.WriteOK(nil)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	e.Log.Debug("Wrote OK.")
	serverConn, err := e.connect(ctx, sessionCtx)
	if err != nil {
		return trace.Wrap(err)
	}
	e.Log.Debugf("Connected: %#v.", serverConn)
	// Copy between the connections.
	go io.Copy(proxyConn.Conn.Conn, serverConn.Conn.Conn)
	_, err = io.Copy(serverConn.Conn.Conn, proxyConn.Conn.Conn)
	if err != nil {
		return trace.Wrap(err)
	}
	e.Log.Debug("Exit.")
	return nil
}

func (e *Engine) checkAccess(sessionCtx *session.Context) error {
	err := sessionCtx.Checker.CheckAccessToDatabase(sessionCtx.Server,
		sessionCtx.DatabaseName, sessionCtx.DatabaseUser)
	if err != nil {
		if err := e.OnSessionStart(*sessionCtx, err); err != nil {
			e.Log.WithError(err).Error("Failed to emit audit event.")
		}
		return trace.Wrap(err)
	}
	return nil
}

func (e *Engine) connect(ctx context.Context, sessionCtx *session.Context) (*client.Conn, error) {
	tlsConfig, err := e.getTLSConfig(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	conn, err := client.Connect(sessionCtx.Server.GetURI(),
		sessionCtx.DatabaseUser,
		"",
		sessionCtx.DatabaseName,
		func(conn *client.Conn) {
			conn.SetTLSConfig(tlsConfig)
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return conn, nil
}

// getAWSAuthToken returns authorization token that will be used as a password
// when connecting to RDS/Aurora databases.
func (e *Engine) getAWSAuthToken(sessionCtx *session.Context) (string, error) {
	e.Log.Debugf("Generating auth token for %s.", sessionCtx)
	return rdsutils.BuildAuthToken(
		sessionCtx.Server.GetURI(),
		sessionCtx.Server.GetRegion(),
		sessionCtx.DatabaseUser,
		e.Credentials)
}

// getTLSConfig builds the client TLS configuration for the session.
//
// For RDS/Aurora, the config must contain RDS root certificate as a trusted
// authority. For onprem we generate a client certificate signed by the host
// CA used to authenticate.
func (e *Engine) getTLSConfig(ctx context.Context, sessionCtx *session.Context) (*tls.Config, error) {
	addr, err := utils.ParseAddr(sessionCtx.Server.GetURI())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig := &tls.Config{
		ServerName: addr.Host(),
		RootCAs:    x509.NewCertPool(),
	}
	// Add CA certificate to the trusted pool if it's present, e.g. when
	// connecting to RDS/Aurora which require AWS CA.
	if len(sessionCtx.Server.GetCA()) != 0 {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(sessionCtx.Server.GetCA()) {
			return nil, trace.BadParameter("failed to append CA certificate to the pool")
		}
	} else if sessionCtx.Server.IsAWS() {
		if rdsCA, ok := e.RDSCACerts[sessionCtx.Server.GetRegion()]; ok {
			if !tlsConfig.RootCAs.AppendCertsFromPEM(rdsCA) {
				return nil, trace.BadParameter("failed to append CA certificate to the pool")
			}
		} else {
			e.Log.Warnf("No RDS CA certificate for %v.", sessionCtx.Server)
		}
	}
	// RDS/Aurora auth is done via an auth token so don't generate a client
	// certificate and exit here.
	if sessionCtx.Server.IsAWS() {
		return tlsConfig, nil
	}
	// Otherwise, when connecting to an onprem database, generate a client
	// certificate. The database instance should be configured with
	// Teleport's CA obtained with 'tctl auth sign --type=db'.
	cert, cas, err := e.getClientCert(ctx, sessionCtx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.Certificates = []tls.Certificate{*cert}
	for _, ca := range cas {
		if !tlsConfig.RootCAs.AppendCertsFromPEM(ca) {
			return nil, trace.BadParameter("failed to append CA certificate to the pool")
		}
	}
	return tlsConfig, nil
}

// getClientCert signs an ephemeral client certificate used by this
// server to authenticate with the database instance.
func (e *Engine) getClientCert(ctx context.Context, sessionCtx *session.Context) (cert *tls.Certificate, cas [][]byte, err error) {
	privateBytes, _, err := native.GenerateKeyPair("")
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// Postgres requires the database username to be encoded as a common
	// name in the client certificate.
	subject := pkix.Name{CommonName: sessionCtx.DatabaseUser}
	csr, err := tlsca.GenerateCertificateRequestPEM(subject, privateBytes)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	// TODO(r0mant): Cache database certificates to avoid expensive generate
	// operation on each connection.
	e.Log.Debugf("Generating client certificate for %s.", sessionCtx)
	resp, err := e.AuthClient.GenerateDatabaseCert(ctx, &proto.DatabaseCertRequest{
		CSR: csr,
		TTL: proto.Duration(sessionCtx.Identity.Expires.Sub(e.Clock.Now())),
	})
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	clientCert, err := tls.X509KeyPair(resp.Cert, privateBytes)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return &clientCert, resp.CACerts, nil
}
