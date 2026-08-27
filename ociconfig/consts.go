package ociconfig

// OCI CLI environment variables (used by oci-cli-env-provider)
const (
	// OCICLIConfigFile is the environment variable for OCI CLI config file path
	OCICLIConfigFile = "OCI_CLI_CONFIG_FILE"
	// OCICLIProfile is the environment variable for OCI CLI profile name
	OCICLIProfile = "OCI_CLI_PROFILE"
	// OCICLITenancy is the environment variable for OCI CLI tenancy OCID
	OCICLITenancy = "OCI_CLI_TENANCY"
	// OCICLIUser is the environment variable for OCI CLI user OCID
	OCICLIUser = "OCI_CLI_USER"
	// OCICLIRegion is the environment variable for OCI CLI region
	OCICLIRegion = "OCI_CLI_REGION"
	// OCICLIFingerprint is the environment variable for OCI CLI key fingerprint
	OCICLIFingerprint = "OCI_CLI_FINGERPRINT"
	// OCICLIKeyFile is the environment variable for OCI CLI private key file path
	OCICLIKeyFile = "OCI_CLI_KEY_FILE"
)

// OCI native SDK environment variables (lowercase after OCI_ prefix)
const (
	// OCITenancyOCID is the environment variable for OCI tenancy OCID (OCI_tenancy_ocid)
	OCITenancyOCID = "OCI_tenancy_ocid"
	// OCIUserOCID is the environment variable for OCI user OCID (OCI_user_ocid)
	OCIUserOCID = "OCI_user_ocid"
	// OCIRegion is the environment variable for OCI region (OCI_region)
	OCIRegion = "OCI_region"
	// OCIFingerprint is the environment variable for OCI key fingerprint (OCI_fingerprint)
	OCIFingerprint = "OCI_fingerprint"
	// OCIPrivateKeyPath is the environment variable for OCI private key path (OCI_private_key_path)
	OCIPrivateKeyPath = "OCI_private_key_path"
)

// Home directories. Both must be redirected when tests isolate the default
// config file lookup: the SDK resolves the home directory via HOME on POSIX
// and USERPROFILE on Windows.
const (
	// HomeEnv is the HOME environment variable
	HomeEnv = "HOME"
	// UserProfileEnv is the USERPROFILE environment variable (Windows)
	UserProfileEnv = "USERPROFILE"
)
