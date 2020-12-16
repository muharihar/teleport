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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"strings"

	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/srv/db/mysql/protocol"

	"github.com/siddontang/go-mysql/mysql"
	"github.com/siddontang/go-mysql/server"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// Proxy proxies connections from MySQL clients to database services
// over reverse tunnel. It runs inside Teleport proxy service.
//
// Implements db.DatabaseProxy.
type Proxy struct {
	// TLSConfig is the proxy TLS configuration.
	TLSConfig *tls.Config
	// Middleware is the auth middleware.
	Middleware *auth.Middleware
	// ConnectToSite is used to connect to remote database server over reverse tunnel.
	ConnectToSite func(context.Context, string, string) (net.Conn, error)
	// Log is used for logging.
	Log logrus.FieldLogger
}

type credentialProvider struct{}

func (p *credentialProvider) CheckUsername(_ string) (bool, error)         { return true, nil }
func (p *credentialProvider) GetCredential(_ string) (string, bool, error) { return "", true, nil }

// HandleConnection accepts connection from a Postgres client, authenticates
// it and proxies it to an appropriate database service.
func (p *Proxy) HandleConnection(ctx context.Context, clientConn net.Conn) (err error) {
	conn := server.MakeConn(
		clientConn,
		server.NewServer("Teleport-1.2.3", mysql.DEFAULT_COLLATION_ID, mysql.AUTH_NATIVE_PASSWORD, nil, p.TLSConfig),
		&credentialProvider{},
		server.EmptyHandler{})
	err = conn.WriteInitialHandshake()
	if err != nil {
		return trace.Wrap(err)
	}
	err = conn.ReadHandshakeResponse()
	if err != nil {
		return trace.Wrap(err)
	}
	tlsConn, ok := conn.Conn.Conn.(*tls.Conn)
	if !ok {
		return trace.BadParameter("expected tls connection")
	}
	ctx, err = p.Middleware.WrapContext(ctx, tlsConn)
	if err != nil {
		return trace.Wrap(err)
	}
	siteConn, err := p.ConnectToSite(ctx, conn.GetUser(), conn.GetDatabase())
	if err != nil {
		return trace.Wrap(err)
	}
	defer siteConn.Close()
	err = p.proxyToSite(ctx, tlsConn, siteConn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil

	// err = conn.WriteOK(nil)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// return nil
}

func (p *Proxy) getPublicKey() []byte {
	certPEM := p.TLSConfig.Certificates[0].Certificate[0]
	block, _ := pem.Decode(certPEM)
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(crt.PublicKey.(*rsa.PublicKey))
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKey})
}

// HandleConnection accepts connection from a Postgres client, authenticates
// it and proxies it to an appropriate database service.
func (p *Proxy) HandleConnection2(ctx context.Context, clientConn net.Conn) (err error) {
	_, err = clientConn.Write(protocol.NewHandshakeV10().Encode())
	if err != nil {
		return trace.Wrap(err)
	}
	packet, err := protocol.ReadPacket(clientConn)
	if err != nil {
		return trace.Wrap(err)
	}
	sslRequest, err := protocol.UnpackSSLRequest(packet)
	if err != nil {
		return trace.Wrap(err)
	}
	p.Log.Debugf("%#v", sslRequest)
	// Upgrade connection to TLS.
	tlsConn := tls.Server(clientConn, p.TLSConfig)
	err = tlsConn.Handshake()
	if err != nil {
		return trace.Wrap(err)
	}
	ctx, err = p.Middleware.WrapContext(ctx, tlsConn)
	if err != nil {
		return trace.Wrap(err)
	}
	siteConn, err := p.ConnectToSite(ctx, "", "")
	if err != nil {
		return trace.Wrap(err)
	}
	defer siteConn.Close()
	err = p.proxyToSite(ctx, tlsConn, siteConn)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil

	packet, err = protocol.ReadPacket(clientConn)
	if err != nil {
		return trace.Wrap(err)
	}
	handshakeResponse, err := protocol.UnpackHandshakeResponse41(packet)
	if err != nil {
		return trace.Wrap(err)
	}
	p.Log.Debugf("%#v", handshakeResponse)
	_, err = clientConn.Write(protocol.NewOKPacket().Encode())
	if err != nil {
		return trace.Wrap(err)
	}
	packet, err = protocol.ReadPacket(clientConn)
	if err != nil {
		return trace.Wrap(err)
	}
	p.Log.Debugf("%v", packet)
	return trace.NotImplemented("not implemented")
	// startupMessage, tlsConn, backend, err := p.handleStartup(ctx, clientConn)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// defer func() {
	// 	if err != nil {
	// 		if err := backend.Send(toErrorResponse(err)); err != nil {
	// 			p.Log.WithError(err).Warn("Failed to send error to backend.")
	// 		}
	// 	}
	// }()
	// ctx, err = p.Middleware.WrapContext(ctx, tlsConn)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// siteConn, err := p.ConnectToSite(ctx)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// defer siteConn.Close()
	// err = p.proxyToSite(ctx, tlsConn, siteConn, startupMessage)
	// if err != nil {
	// 	return trace.Wrap(err)
	// }
	// return nil
}

// proxyToSite starts proxying all traffic received from Postgres client
// between this proxy and Teleport database service over reverse tunnel.
func (p *Proxy) proxyToSite(ctx context.Context, clientConn, siteConn net.Conn) (retErr error) {
	errCh := make(chan error, 2)
	go func() {
		defer p.Log.Debug("Stop proxying from client to site.")
		defer siteConn.Close()
		defer clientConn.Close()
		_, err := io.Copy(siteConn, clientConn)
		errCh <- err
	}()
	go func() {
		defer p.Log.Debug("Stop proxying from site to client.")
		defer siteConn.Close()
		defer clientConn.Close()
		_, err := io.Copy(clientConn, siteConn)
		errCh <- err
	}()
	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				p.Log.WithError(err).Warn("Connection problem.")
				errs = append(errs, err)
			}
		case <-ctx.Done():
			return trace.ConnectionProblem(nil, "context is closing")
		}
	}
	return trace.NewAggregate(errs...)
}
