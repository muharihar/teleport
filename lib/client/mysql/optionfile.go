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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/pgservicefile"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"gopkg.in/ini.v1"
)

// Add updates Postgres connection service file at the default location with
// the connection information for the provided profile.
func Add(cluster, name, user, database string, profile client.ProfileStatus, quiet bool) error {
	serviceFile, err := Load()
	if err != nil {
		return trace.Wrap(err)
	}
	addr, err := utils.ParseAddr(profile.ProxyURL.Host)
	if err != nil {
		return trace.Wrap(err)
	}
	connectProfile := pgservicefile.ConnectProfile{
		Name:        serviceName(cluster, name),
		Host:        addr.Host(),
		Port:        addr.Port(defaults.HTTPListenPort),
		User:        user,
		Database:    database,
		Insecure:    false, // TODO(r0mant): Support insecure mode.
		SSLRootCert: profile.CACertPath(),
		SSLCert:     profile.DatabaseCertPath(name),
		SSLKey:      profile.KeyPath(),
	}
	err = serviceFile.Upsert(connectProfile)
	if err != nil {
		return trace.Wrap(err)
	}
	if quiet {
		return nil
	}
	return messageTpl.Execute(os.Stdout, connectProfile)
}

// Env returns environment variables for the provided Postgres service from
// the default connection service file.
func Env(cluster, name string) (map[string]string, error) {
	serviceFile, err := Load()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	env, err := serviceFile.Env(serviceName(cluster, name))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return env, nil
}

// Delete deletes specified connection profile from the default Postgres
// service file.
func Delete(cluster, name string) error {
	serviceFile, err := Load()
	if err != nil {
		return trace.Wrap(err)
	}
	err = serviceFile.Delete(serviceName(cluster, name))
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func serviceName(cluster, name string) string {
	return fmt.Sprintf("%v-%v", cluster, name)
}

// OptionFile represents MySQL option file.
//
// https://dev.mysql.com/doc/refman/8.0/en/option-files.html
type OptionFile struct {
	// iniFile is the underlying ini file.
	iniFile *ini.File
	// path is the service file path.
	path string
}

// Load loads MySQL option file from the default location.
func Load() (*OptionFile, error) {
	// Default location is .my.cnf file in the user's home directory.
	user, err := user.Current()
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	return LoadFromPath(filepath.Join(user.HomeDir, mysqlOptionFile))
}

// LoadFromPath loads MySQL option file from the specified path.
func LoadFromPath(path string) (*OptionFile, error) {
	// Loose load will ignore file not found error.
	iniFile, err := ini.LoadSources(ini.LoadOptions{
		Loose:            true,
		AllowBooleanKeys: true,
	}, path)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &OptionFile{
		iniFile: iniFile,
		path:    path,
	}, nil
}

//
func (o *OptionFile) Upsert(profile pgservicefile.ConnectProfile) error {
	name := "client_" + profile.Name
	section := o.iniFile.Section(name)
	if section != nil {
		o.iniFile.DeleteSection(profile.Name)
	}
	section, err := o.iniFile.NewSection(name)
	if err != nil {
		return trace.Wrap(err)
	}
	section.NewKey("host", profile.Host)
	section.NewKey("port", strconv.Itoa(profile.Port))
	if profile.User != "" {
		section.NewKey("user", profile.User)
	}
	if profile.Database != "" {
		section.NewKey("database", profile.Database)
	}
	// TODO(r0mant): Add insecure mode.
	section.NewKey("ssl-ca", profile.SSLRootCert)
	section.NewKey("ssl-cert", profile.SSLCert)
	section.NewKey("ssl-key", profile.SSLKey)
	ini.PrettyFormat = false
	return o.iniFile.SaveTo(o.path)
}

//
func (o *OptionFile) Env(name string) (map[string]string, error) {
	_, err := o.iniFile.GetSection("client_" + name)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, trace.NotFound("connection profile %q not found", name)
		}
		return nil, trace.Wrap(err)
	}
	return map[string]string{
		"MYSQL_GROUP_SUFFIX": "_" + name,
	}, nil
}

//
func (o *OptionFile) Delete(name string) error {
	name = "client_" + name
	o.iniFile.DeleteSection(name)
	return o.iniFile.SaveTo(o.path)
}

// mysqlOptionFile is the default name of the MySQL option file.
const mysqlOptionFile = ".my.cnf"

// message is printed after MySQL option file has been updated.
var messageTpl = template.Must(template.New("").Parse(`
Connection information for MySQL database "{{.Name}}" has been saved.

You can now connect to the database using the following command:

  $ mysql --defaults-group-suffix=_{{.Name}}

Or configure environment variables and use regular CLI flags:

  $ eval $(tsh db env)
  $ mysql

`))
