package config

type StoreConfig struct {
	ClusterName       *string  `yaml:clustername,json:"clustername"`
	HostName          *string  `yaml:hostname,json:"hostname"`
	TChannelPort      *string  `yaml:tchannelport,json:"tchannelport"`
	Seed              *string  `yaml:seednodes,json:"seednodes"`
	SyncBuffer        *int     `yaml:syncbuffer,json:"syncbuffer"`
	NodeId            *string  `yaml:nodeid,json:"nodeid"`
	Buckets           *int     `yaml:buckets,json:"buckets"`
	StatsDEnabled     *bool    `yaml:statsdenabled,json:"statsdenabled"`
	HttpPort          *int     `yaml:httpport,json:"httpport"`
	UnixSocket        *string  `yaml:httpport,json:"unixsocket"`
	UnixSocketEnable  *bool    `yaml:httpport,json:"unixsocketenable"`
	UnsyncedCtrLimit  *int32   `yaml:unsyncedctrlimit,json:"unsyncedctrlimit"`
	UnsyncedTimeLimit *int     `yaml:unsyncedtimelimit,json:"unsyncedtimelimit"`
	StatsDHostPort    *string  `yaml:statsdhostport,json:"statsdhostport"`
	StatsDSampleRate  *float32 `yaml:statsdsamplerate,json:"statsdsamplerate"`
	StatsDBucket      *string  `yaml:statsdbucket,json:"statsdbucket"`
	GcInterval        *int     `yaml:gcinterval,json:"gcinterval"`
	ApiSecret         *string  `yaml:apisecret,json:"apisecret"`
	GcGrace           *int     `yaml:gcgrace,json:"gcgrace"`
	ProxyPath         *string  `yaml:proxypath,json:"proxypath"`
}
