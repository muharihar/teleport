/*
Copyright 2015 Gravitational, Inc.

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

package teleport

import (
	"github.com/gravitational/teleport/api/constants"
)

// Role identifies the role of an SSH connection. Unlike "user roles"
// introduced as part of RBAC in Teleport 1.4+ these are built-in roles used
// for different Teleport components when connecting to each other.
type Role = constants.Role
type Roles = constants.Roles

var (
	RoleAuth               = constants.RoleAuth
	RoleWeb                = constants.RoleWeb
	RoleNode               = constants.RoleNode
	RoleProxy              = constants.RoleProxy
	RoleAdmin              = constants.RoleAdmin
	RoleProvisionToken     = constants.RoleProvisionToken
	RoleTrustedCluster     = constants.RoleTrustedCluster
	RoleSignup             = constants.RoleSignup
	RoleNop                = constants.RoleNop
	RoleRemoteProxy        = constants.RoleRemoteProxy
	RoleKube               = constants.RoleKube
	RoleApp                = constants.RoleApp
	LegacyClusterTokenType = constants.LegacyClusterTokenType
	NewRoles               = constants.NewRoles
	ParseRoles             = constants.ParseRoles
)
