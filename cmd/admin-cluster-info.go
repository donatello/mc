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

import (
	"fmt"

	"github.com/minio/cli"
)

var adminClusterInfoCmd = cli.Command{
	Name:         "info",
	Usage:        "fetch multi-cluster configuration info",
	Action:       mainAdminClusterInfo,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        globalFlags,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Display multi-cluster configuration info
     {{.Prompt}} {{.HelpName}} myminio
`,
}

func checkAdminClusterInfoSyntax(ctx *cli.Context) {
	argsNr := len(ctx.Args())
	if argsNr != 1 {
		fatalIf(errInvalidArgument().Trace(ctx.Args().Tail()...),
			"Incorrect number of arguments for cluster info command.")
	}
}

func mainAdminClusterInfo(ctx *cli.Context) error {
	checkAdminClusterInfoSyntax(ctx)

	return fmt.Errorf("Not implemented!")
	args := ctx.Args()
	aliasedURL := args.Get(0)

	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	fmt.Println(client.ClusterInfo(globalContext))
	fmt.Println("Not implemented")

	return nil
}
