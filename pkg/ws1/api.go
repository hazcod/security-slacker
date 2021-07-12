package ws1

type DevicesResponse struct {
	Devices  []Devices `json:"Devices"`
	Page     int       `json:"Page"`
	PageSize int       `json:"PageSize"`
	Total    int       `json:"Total"`
}

type ID struct {
	Value int `json:"Value"`
}
type LocationGroupID struct {
	ID   ID     `json:"Id"`
	Name string `json:"Name"`
	UUID string `json:"Uuid"`
}
type UserID struct {
	ID   ID     `json:"Id"`
	Name string `json:"Name"`
	UUID string `json:"Uuid"`
}
type PlatformID struct {
	ID   ID     `json:"Id"`
	Name string `json:"Name"`
}
type ModelID struct {
	ID   ID     `json:"Id"`
	Name string `json:"Name"`
}
type DeviceMCC struct {
	Simmcc     string `json:"SIMMCC"`
	CurrentMCC string `json:"CurrentMCC"`
}
type DeviceCellularNetworkInfo struct {
	CarrierName string    `json:"CarrierName"`
	CardID      string    `json:"CardId"`
	PhoneNumber string    `json:"PhoneNumber"`
	DeviceMCC   DeviceMCC `json:"DeviceMCC"`
	IsRoaming   bool      `json:"IsRoaming"`
}
type DeviceCompliance struct {
	CompliantStatus     bool          `json:"CompliantStatus"`
	PolicyName          string        `json:"PolicyName"`
	PolicyDetail        string        `json:"PolicyDetail"`
	LastComplianceCheck string        `json:"LastComplianceCheck"`
	NextComplianceCheck string        `json:"NextComplianceCheck"`
	ActionTaken         []interface{} `json:"ActionTaken"`
	ID                  ID            `json:"Id"`
	UUID                string        `json:"Uuid"`
}
type ComplianceSummary struct {
	DeviceCompliance []DeviceCompliance `json:"DeviceCompliance"`
}
type EasIds struct {
	EasID []string `json:"EasId"`
}
type Devices struct {
	TimeZone                         string                      `json:"TimeZone"`
	Udid                             string                      `json:"Udid"`
	SerialNumber                     string                      `json:"SerialNumber"`
	MacAddress                       string                      `json:"MacAddress"`
	Imei                             string                      `json:"Imei"`
	EasID                            string                      `json:"EasId"`
	AssetNumber                      string                      `json:"AssetNumber"`
	DeviceFriendlyName               string                      `json:"DeviceFriendlyName"`
	DeviceReportedName               string                      `json:"DeviceReportedName"`
	LocationGroupID                  LocationGroupID             `json:"LocationGroupId"`
	LocationGroupName                string                      `json:"LocationGroupName"`
	UserID                           UserID                      `json:"UserId"`
	UserName                         string                      `json:"UserName"`
	DataProtectionStatus             int                         `json:"DataProtectionStatus"`
	UserEmailAddress                 string                      `json:"UserEmailAddress"`
	Ownership                        string                      `json:"Ownership"`
	PlatformID                       PlatformID                  `json:"PlatformId"`
	Platform                         string                      `json:"Platform"`
	ModelID                          ModelID                     `json:"ModelId"`
	Model                            string                      `json:"Model"`
	OperatingSystem                  string                      `json:"OperatingSystem"`
	PhoneNumber                      string                      `json:"PhoneNumber"`
	LastSeen                         string                      `json:"LastSeen"`
	EnrollmentStatus                 string                      `json:"EnrollmentStatus"`
	ComplianceStatus                 string                      `json:"ComplianceStatus"`
	CompromisedStatus                bool                        `json:"CompromisedStatus"`
	LastEnrolledOn                   string                      `json:"LastEnrolledOn"`
	LastComplianceCheckOn            string                      `json:"LastComplianceCheckOn"`
	LastCompromisedCheckOn           string                      `json:"LastCompromisedCheckOn"`
	IsSupervised                     bool                        `json:"IsSupervised"`
	VirtualMemory                    int                         `json:"VirtualMemory"`
	OEMInfo                          string                      `json:"OEMInfo"`
	DeviceCapacity                   float64                     `json:"DeviceCapacity,omitempty"`
	AvailableDeviceCapacity          float64                     `json:"AvailableDeviceCapacity,omitempty"`
	IsDeviceDNDEnabled               bool                        `json:"IsDeviceDNDEnabled"`
	IsDeviceLocatorEnabled           bool                        `json:"IsDeviceLocatorEnabled"`
	IsCloudBackupEnabled             bool                        `json:"IsCloudBackupEnabled"`
	IsActivationLockEnabled          bool                        `json:"IsActivationLockEnabled"`
	IsNetworkTethered                bool                        `json:"IsNetworkTethered"`
	BatteryLevel                     string                      `json:"BatteryLevel"`
	IsRoaming                        bool                        `json:"IsRoaming"`
	SystemIntegrityProtectionEnabled bool                        `json:"SystemIntegrityProtectionEnabled"`
	ProcessorArchitecture            int                         `json:"ProcessorArchitecture"`
	TotalPhysicalMemory              int                         `json:"TotalPhysicalMemory"`
	AvailablePhysicalMemory          int                         `json:"AvailablePhysicalMemory"`
	OSBuildVersion                   string                      `json:"OSBuildVersion"`
	DeviceCellularNetworkInfo        []DeviceCellularNetworkInfo `json:"DeviceCellularNetworkInfo,omitempty"`
	EnrollmentUserUUID               string                      `json:"EnrollmentUserUuid"`
	ManagedBy                        int                         `json:"ManagedBy"`
	WifiSsid                         string                      `json:"WifiSsid"`
	ID                               ID                          `json:"Id"`
	UUID                             string                      `json:"Uuid"`
	ComplianceSummary                ComplianceSummary           `json:"ComplianceSummary,omitempty"`
}
