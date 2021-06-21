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
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/minio/cli"
)

var idpLDAPCheckCmd = cli.Command{
	Name:         "check",
	Usage:        "check LDAP configuration variables for the server",
	Action:       mainIdpLdapCheck,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(checkFlags, globalFlags...),
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS]

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Check simple LDAP configuration.
     {{.Prompt}} {{.HelpName}} \
          --server-addr=myldap.com:636 \
          --lookup-bind-dn='cn=admin,dc=example,dc=com' \
          --lookup-bind-password='secret' \
          --user-dn-search-base-dn='dc=example,dc=com' \
          --user-dn-search-filter='(uid=%s)' \
          --test-user-name johndoe \
          --test-user-password johndoesecret
  2. Check another simple LDAP configuration with group search, parameters specified via environment.
     {{.Prompt}} export MINIO_IDENTITY_LDAP_SERVER_ADDR=localhost:389
     {{.Prompt}} export MINIO_IDENTITY_LDAP_SERVER_INSECURE=on
     {{.Prompt}} export MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN=cn=admin,dc=min,dc=io
     {{.Prompt}} export MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD=admin
     {{.Prompt}} export MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN=dc=min,dc=io
     {{.Prompt}} export MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER=(uid=%s)
     {{.Prompt}} export MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN=ou=swengg,dc=min,dc=io
     {{.Prompt}} export MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER=(&(objectclass=groupOfNames)(member=%d))
     {{.Prompt}} {{.HelpName}} \
          --test-user-name dillon \
          --test-user-password dillon
`,
}

// LDAP keys and envs.
const (
	GroupSearchBaseDN  = "group_search_base_dn"
	GroupSearchFilter  = "group_search_filter"
	LookupBindDN       = "lookup_bind_dn"
	LookupBindPassword = "lookup_bind_password"
	STSExpiry          = "sts_expiry"
	ServerAddr         = "server_addr"
	ServerInsecure     = "server_insecure"
	ServerStartTLS     = "server_starttls"
	TLSSkipVerify      = "tls_skip_verify"
	UserDNSearchBaseDN = "user_dn_search_base_dn"
	UserDNSearchFilter = "user_dn_search_filter"
	UsernameFormat     = "username_format"

	TestUserName     = "test_user_name"
	TestUserPassword = "test_user_password"

	EnvGroupSearchBaseDN  = "MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN"
	EnvGroupSearchFilter  = "MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER"
	EnvLookupBindDN       = "MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN"
	EnvLookupBindPassword = "MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD"
	EnvSTSExpiry          = "MINIO_IDENTITY_LDAP_STS_EXPIRY"
	EnvServerAddr         = "MINIO_IDENTITY_LDAP_SERVER_ADDR"
	EnvServerInsecure     = "MINIO_IDENTITY_LDAP_SERVER_INSECURE"
	EnvServerStartTLS     = "MINIO_IDENTITY_LDAP_SERVER_STARTTLS"
	EnvTLSSkipVerify      = "MINIO_IDENTITY_LDAP_TLS_SKIP_VERIFY"
	EnvUserDNSearchBaseDN = "MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN"
	EnvUserDNSearchFilter = "MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER"
	EnvUsernameFormat     = "MINIO_IDENTITY_LDAP_USERNAME_FORMAT"

	EnvTestUserName     = "TEST_USER_NAME"
	EnvTestUserPassword = "TEST_USER_PASSWORD"
)

type envVal struct {
	Name  string
	Value string
}

type configParam struct {
	Name          string
	Env           string
	StringValue   string
	BoolValue     bool
	DurationValue time.Duration
	HelpMessage   string
}

func (cp *configParam) getOpt() string {
	return strings.ReplaceAll(cp.Name, "_", "-")
}

func (cp *configParam) toStringFlag() cli.StringFlag {
	return cli.StringFlag{
		Name:        cp.getOpt(),
		Usage:       cp.HelpMessage,
		EnvVar:      cp.Env,
		Destination: &cp.StringValue,
	}
}

func (cp *configParam) toBoolFlag() cli.BoolFlag {
	// Since the cli library does not support parsing "on" as true and "off"
	// as false, we don't load from the env via the cli library. This is
	// done instead as a post flag parsing step via `checkBoolEnvVar`
	return cli.BoolFlag{
		Name:  cp.getOpt(),
		Usage: fmt.Sprintf("%s [$%s]", cp.HelpMessage, cp.Env),
		// EnvVar:      cp.Env,
		Destination: &cp.BoolValue,
	}
}

// checkBoolEnvVar helps support parsing "on" and "off" as booleans from the
// environment.
func (cp *configParam) checkBoolEnvVar() error {
	envVal, present := os.LookupEnv(cp.Env)
	if !present {
		return nil
	}

	switch strings.ToLower(envVal) {
	case "on":
		cp.BoolValue = true
	case "off":
		cp.BoolValue = false
	default:
		val, err := strconv.ParseBool(envVal)
		if err != nil {
			return fmt.Errorf("Error parsing environment variable %s as a boolean: %s", cp.Env, err)
		}
		cp.BoolValue = val
	}
	return nil
}

func (cp *configParam) toDurationFlag() cli.DurationFlag {
	return cli.DurationFlag{
		Name:        cp.getOpt(),
		Usage:       cp.HelpMessage,
		EnvVar:      cp.Env,
		Destination: &cp.DurationValue,
	}
}

func (cp *configParam) getEnvVal() *envVal {
	if cp.StringValue != "" {
		return &envVal{cp.Env, cp.StringValue}
	}
	if cp.BoolValue {
		return &envVal{cp.Env, "on"}
	}
	if cp.DurationValue != 0 {
		return &envVal{cp.Env, cp.DurationValue.String()}
	}
	return nil
}

var (
	serverAddrCP = configParam{
		Name:        ServerAddr,
		Env:         EnvServerAddr,
		HelpMessage: "Address of the LDAP server e.g. \"myldapserver:636\"",
	}
	tlsSkipVerifyCP = configParam{
		Name:        TLSSkipVerify,
		Env:         EnvTLSSkipVerify,
		HelpMessage: "Skip verifying the TLS certificate of LDAP server",
	}
	serverInsecureCP = configParam{
		Name:        ServerInsecure,
		Env:         EnvServerInsecure,
		HelpMessage: "Indicate that LDAP server uses plaintext communication",
	}
	serverStartTLSCP = configParam{
		Name:        ServerStartTLS,
		Env:         EnvServerStartTLS,
		HelpMessage: "Indicate that LDAP server should be accessed in StartTLS mode",
	}
	lookupBindDNCP = configParam{
		Name:        LookupBindDN,
		Env:         EnvLookupBindDN,
		HelpMessage: "Distinguished Name (DN) of an LDAP service account",
	}
	lookupBindPasswordCP = configParam{
		Name:        LookupBindPassword,
		Env:         EnvLookupBindPassword,
		HelpMessage: "Password for the LDAP service account",
	}
	userDNSearchBaseDNCP = configParam{
		Name:        UserDNSearchBaseDN,
		Env:         EnvUserDNSearchBaseDN,
		HelpMessage: "Search base DN to look for user DNs",
	}
	userDNSearchFilterCP = configParam{
		Name:        UserDNSearchFilter,
		Env:         EnvUserDNSearchFilter,
		HelpMessage: "LDAP search filter to find user DNs given their username",
	}
	groupSearchBaseDNCP = configParam{
		Name:        GroupSearchBaseDN,
		Env:         EnvGroupSearchBaseDN,
		HelpMessage: "Search base DN to look for user groups",
	}
	groupSearchFilterCP = configParam{
		Name:        GroupSearchFilter,
		Env:         EnvGroupSearchFilter,
		HelpMessage: "LDAP search filter to find user groups given their username or DN",
	}
	stsExpiryCP = configParam{
		Name:        STSExpiry,
		Env:         EnvSTSExpiry,
		HelpMessage: "Validity duration of any credentials generated for LDAP",
	}

	testUserNameCP = configParam{
		Name:        TestUserName,
		Env:         EnvTestUserName,
		HelpMessage: "Username to test LDAP authentication similar to MinIO server",
	}
	testUserPasswordCP = configParam{
		Name:        TestUserPassword,
		Env:         EnvTestUserPassword,
		HelpMessage: "Password of user to test LDAP authentication similar to MinIO server",
	}
)

var (
	minioServerConfigParams = []*configParam{
		&serverAddrCP,
		&tlsSkipVerifyCP,
		&serverInsecureCP,
		&serverStartTLSCP,
		&lookupBindDNCP,
		&lookupBindPasswordCP,
		&userDNSearchBaseDNCP,
		&userDNSearchFilterCP,
		&groupSearchBaseDNCP,
		&groupSearchFilterCP,
		&stsExpiryCP,
	}
)

func getConfigEnvs() []envVal {
	var res []envVal
	for _, cp := range minioServerConfigParams {
		v := cp.getEnvVal()
		if v != nil {
			res = append(res, *v)
		}
	}
	return res
}

var (
	checkFlags = []cli.Flag{
		serverAddrCP.toStringFlag(),
		lookupBindDNCP.toStringFlag(),
		lookupBindPasswordCP.toStringFlag(),
		userDNSearchBaseDNCP.toStringFlag(),
		userDNSearchFilterCP.toStringFlag(),
		testUserNameCP.toStringFlag(),
		testUserPasswordCP.toStringFlag(),
		groupSearchBaseDNCP.toStringFlag(),
		groupSearchFilterCP.toStringFlag(),
		tlsSkipVerifyCP.toBoolFlag(),
		serverInsecureCP.toBoolFlag(),
		serverStartTLSCP.toBoolFlag(),
		stsExpiryCP.toDurationFlag(),
	}
)

type checkMessage struct {
	Title    string
	Messages []string
	Error    error
}

func (c *checkMessage) addMessage(s string) {
	c.Messages = append(c.Messages, s)
}

func (c *checkMessage) addError(s string, err error) {
	c.Messages = append(c.Messages, s)
	c.Error = err
}

var (
	checks = []struct {
		cm        checkMessage
		checkFunc func(*checkMessage)
	}{
		{
			checkMessage{Title: "Check LDAP server connectivity"},
			getLDAPConn,
		},
		{
			checkMessage{Title: "Check Lookup Bind credentials"},
			getLookupBind,
		},
		{
			checkMessage{Title: "Check test user credentials"},
			checkTestUser,
		},
		{
			checkMessage{Title: "Lookup test user's groups"},
			lookupUserGroups,
		},
	}

	conn *ldap.Conn

	validatedTestUserDN string
)

func getLDAPConn(res *checkMessage) {

	{
		// Parse environment variables for boolean flags here.
		for _, cp := range []*configParam{&tlsSkipVerifyCP, &serverInsecureCP, &serverStartTLSCP} {
			err := cp.checkBoolEnvVar()
			if err != nil {
				res.addError("Invalid parameter", err)
				return
			}
			// fmt.Printf("%#v\n", cp)
		}
	}

	var err error
	serverHost, _, terr := net.SplitHostPort(serverAddrCP.StringValue)
	if terr != nil {
		serverHost = serverAddrCP.StringValue
		res.addMessage("No port was specified in server address, assuming 636.")
		serverAddrCP.StringValue = net.JoinHostPort(serverAddrCP.StringValue, "636")
	}

	if serverInsecureCP.BoolValue {
		conn, err = ldap.Dial("tcp", serverAddrCP.StringValue)
		if err != nil {
			res.addError("Error connecting to server", err)
		}
		return
	}

	// In case server is insecure and user forgot to set this option
	// here, they will get an obscure "EOF" error message, so we add
	// an info message to warn the user.
	res.addMessage("Assuming server is using TLS")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: tlsSkipVerifyCP.BoolValue,
		ServerName:         serverHost,
	}

	if serverStartTLSCP.BoolValue {
		conn, err = ldap.Dial("tcp", serverAddrCP.StringValue)
		if err != nil {
			res.addError("Error connecting to server", err)
			return
		}
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			res.addError("Error enabling StartTLS", err)
			return
		}
	} else {
		conn, err = ldap.DialTLS("tcp", serverAddrCP.StringValue, tlsConfig)
		if err != nil {
			res.addError("Error connecting to server", err)
			return
		}
	}
}

func ldapBind(dn, password string) error {
	if password == "" {
		return conn.UnauthenticatedBind(dn)
	}
	return conn.Bind(dn, password)
}

func getLookupBind(cm *checkMessage) {
	dn := lookupBindDNCP.StringValue
	password := lookupBindPasswordCP.StringValue
	var err error
	if dn == "" {
		err = errors.New("Lookup Bind User DN is empty.")
		cm.addError("LDAP Lookup Bind user invalid credentials", err)
		return
	}
	err = ldapBind(dn, password)
	if ldap.IsErrorWithCode(err, 49) {
		cm.addError("Lookup Bind user invalid credentials", err)
	} else if err != nil {
		cm.addError("Unhandled error", err)
	}
}

func checkTestUser(cm *checkMessage) {
	searchFilter := userDNSearchFilterCP.StringValue
	searchBase := userDNSearchBaseDNCP.StringValue
	var err error
	if searchFilter == "" || searchBase == "" {
		err = errors.New("Please specify a value for --user-dn-search-filter and --user-dn-search-base-dn parameters")
		cm.addError("Missing params", err)
		return
	}

	if !strings.Contains(searchFilter, "%s") {
		err = errors.New("Search filter is not valid - it must contain a `%s` to substitute the username.")
		cm.addError("Invalid parameter", err)
		return
	}

	testUserName, testUserPassword := testUserNameCP.StringValue, testUserPasswordCP.StringValue
	if testUserName == "" || testUserPassword == "" {
		err = errors.New("Please specify a value for --test-user-name and --test-user-password parameters to test the user search filter")
		cm.addError("Missing params", err)
		return
	}

	// Substitute username in search filter and look for DN
	filter := strings.Replace(searchFilter, "%s", ldap.EscapeFilter(testUserName), -1)
	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{}, // only need DN, so no pass no attributes here
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		cm.addError("Could not find test user's DN with the given search filter", err)
		return
	}
	if len(searchResult.Entries) == 0 {
		err = fmt.Errorf("User DN for %s not found", testUserName)
		cm.addError("User not found", err)
		return
	}
	if len(searchResult.Entries) != 1 {
		err = fmt.Errorf("Multiple DNs for %s found - please fix the search filter", testUserName)
		cm.addError("Too many users found", err)
		return
	}
	userDN := searchResult.Entries[0].DN
	cm.addMessage(fmt.Sprintf("Found DN: `%s`", userDN))

	// Verify credential of user.
	err = ldapBind(userDN, testUserPassword)
	if ldap.IsErrorWithCode(err, 49) {
		cm.addError(fmt.Sprintf("Invalid credential for DN `%s`", userDN), err)
		return
	} else if err != nil {
		cm.addError("Unhandled user bind error", err)
		return
	}

	validatedTestUserDN = userDN
}

func getGroups(conn *ldap.Conn, sreq *ldap.SearchRequest) ([]string, error) {
	var groups []string
	sres, err := conn.Search(sreq)
	if err != nil {
		// Check if there is no matching result and return empty slice.
		// Ref: https://ldap.com/ldap-result-code-reference/
		if ldap.IsErrorWithCode(err, 32) {
			return nil, nil
		}
		return nil, err
	}
	for _, entry := range sres.Entries {
		// We only queried one attribute,
		// so we only look up the first one.
		groups = append(groups, entry.DN)
	}
	return groups, nil
}

func lookupUserGroups(cm *checkMessage) {
	groupSearchFilter, groupSearchBase := groupSearchFilterCP.StringValue, groupSearchBaseDNCP.StringValue
	if groupSearchFilter == "" || groupSearchBase == "" {
		cm.addMessage("Please specify --group-search-base-dn and --group-search-filter to look for groups the test user is a member of")
		return
	}

	// Substitute params and lookup groups
	filter := strings.Replace(groupSearchFilter, "%s", ldap.EscapeFilter(testUserNameCP.StringValue), -1)
	filter = strings.Replace(filter, "%d", ldap.EscapeFilter(validatedTestUserDN), -1)
	searchRequest := ldap.NewSearchRequest(
		groupSearchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		nil,
		nil,
	)

	groups, err := getGroups(conn, searchRequest)
	if err != nil {
		cm.addError(fmt.Sprintf("Error finding groups of `%s`", validatedTestUserDN), err)
		return
	}

	if len(groups) == 0 {
		cm.addMessage("Found no groups")
	} else {
		for _, group := range groups {
			cm.addMessage(fmt.Sprintf("Found group: `%s`", group))
		}
	}
}

func displayCheckOutput(cms []checkMessage) error {
	for _, cm := range cms {
		var checkMark string
		if cm.Error != nil {
			checkMark = "❌" // cross mark emoji
		} else {
			checkMark = "✔" // check mark emoji
			// checkMark = "👍" // thumbs up emoji
		}
		checkStatus := fmt.Sprintf("%s %s", checkMark, cm.Title)
		fmt.Println(checkStatus)
		for _, msg := range cm.Messages {
			fmt.Printf("\t[INFO] %s\n", msg)
		}
		if cm.Error != nil {
			fmt.Printf("\t[ERROR DETAIL] %v\n", cm.Error)
			return cm.Error
		}
	}
	return nil
}

func displayVars() {
	fmt.Println("Your validated MinIO LDAP configuration via environment variables is:")
	envs := getConfigEnvs()
	for _, v := range envs {
		fmt.Printf("%s=%v\n", v.Name, v.Value)
	}
}

func mainIdpLdapCheck(ctx *cli.Context) error {
	if serverAddrCP.StringValue == "" {
		cli.ShowCommandHelpAndExit(ctx, "check", 1)
	}

	var outputs []checkMessage
	for _, check := range checks {
		check.checkFunc(&check.cm)
		outputs = append(outputs, check.cm)
		if check.cm.Error != nil {
			break
		}
	}

	err := displayCheckOutput(outputs)
	if err != nil {
		return err
	}

	displayVars()
	return nil
}
