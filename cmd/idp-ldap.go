// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import "github.com/minio/cli"

var idpLDAPSubcommands = []cli.Command{
	idpLDAPCheckCmd,
}

var idpLdapCmd = cli.Command{
	Name:            "ldap",
	Usage:           "utilities for the LDAP IDP provider",
	Action:          mainIdpLdap,
	Before:          setGlobalsFromContext,
	Flags:           globalFlags,
	HideHelpCommand: true,
	Subcommands:     idpLDAPSubcommands,
}

// mainIdpLdap handles "mc idp ldap" command.
func mainIdpLdap(ctx *cli.Context) error {
	commandNotFound(ctx, idpLDAPSubcommands)
	return nil
}
