package rbac

import (
	"github.com/mikespook/gorbac/v2"
)

func SetupRBAC() *gorbac.RBAC {
	rbac := gorbac.New()

	superuser := gorbac.NewStdRole("superuser")
	admin := gorbac.NewStdRole("admin")
	controller := gorbac.NewStdRole("controller")
	driver := gorbac.NewStdRole("driver")

	// TODO: define permissions

	// readUsers := gorbac.NewStdPermission("users:read:all")
	// writeUsers := gorbac.NewStdPermission("users:write:all")
	// admin.Assign(readUsers)
	// admin.Assign(writeUsers)

	rbac.Add(superuser)
	rbac.Add(admin)
	rbac.Add(controller)
	rbac.Add(driver)

	return rbac
}
