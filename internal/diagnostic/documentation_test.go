package diagnostic

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDoctorDocumentationCoversEmittedCodesAndRemediations(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	documentation, err := os.ReadFile(filepath.Join(root, "docs", "doctor.md")) // #nosec G304 -- fixed repository documentation path.
	if err != nil {
		t.Fatal(err)
	}
	sources := []string{
		"cmd/punaro/main.go",
		"cmd/punaro-adapter/doctor.go",
		"cmd/punaro-bootstrap/doctor.go",
		"cmd/punaro-telegram/doctor.go",
		"internal/bootstrap/doctor.go",
		"internal/diagnostic/fleet.go",
	}
	want := map[string]struct{}{}
	for _, relative := range sources {
		file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(relative)), nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		collectDoctorDocumentationIdentifiers(file, want)
	}
	for _, value := range []string{
		"relay_transport", "relay_origin", "relay_access", "relay_enrollment", "relay_protocol",
		"notification_transport", "notification_origin", "notification_access", "notification_enrollment", "notification_protocol",
		"repair_relay_transport", "repair_relay_route", "repair_relay_access", "repair_relay_enrollment",
		"repair_notification_transport", "repair_notification_route", "repair_notification_access", "repair_notification_enrollment",
	} {
		want[value] = struct{}{}
	}
	for value := range want {
		if !strings.Contains(string(documentation), "`"+value+"`") {
			t.Errorf("docs/doctor.md does not document %s", value)
		}
	}
}

func collectDoctorDocumentationIdentifiers(file *ast.File, identifiers map[string]struct{}) {
	codeArguments := map[string]int{
		"Pass": 0, "Fail": 0, "Unavailable": 0, "OptionalFail": 0, "OptionalUnavailable": 0,
		"boolDoctorCheck": 1, "telegramBoolCheck": 1, "appendKnownServerCheck": 1,
		"fleetBoolCheck": 1, "boolBootstrapCheck": 1, "doctorLockCheck": 2,
		"absentBootstrapNodeCheck": 2,
	}
	actionPrefixes := []string{
		"collect_", "complete_", "configure_", "create_", "enable_", "follow_", "free_", "inspect_",
		"install_", "recover_", "refresh_", "regenerate_", "reinstall_", "remove_", "renew_", "repair_",
		"restart_", "restore_", "resume_", "run_supported_", "separate_", "start_", "upgrade_",
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CallExpr:
			name := calledName(typed.Fun)
			if index, ok := codeArguments[name]; ok && index < len(typed.Args) {
				if value, ok := stringLiteral(typed.Args[index]); ok {
					identifiers[value] = struct{}{}
				}
			}
		case *ast.BasicLit:
			value, ok := stringLiteral(typed)
			if !ok || strings.HasSuffix(value, "_") || value == "run_lock" || value == "upgrade_edges" {
				break
			}
			for _, prefix := range actionPrefixes {
				if strings.HasPrefix(value, prefix) {
					identifiers[value] = struct{}{}
					break
				}
			}
		}
		return true
	})
}

func calledName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return typed.Sel.Name
	default:
		return ""
	}
}

func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}
