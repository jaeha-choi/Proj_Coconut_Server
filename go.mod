module github.com/jaeha-choi/Proj_Coconut_Server

go 1.16

require (
	github.com/jaeha-choi/Proj_Coconut_Utility v0.0.0-20210628171604-a61324f5dd3a
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

replace github.com/jaeha-choi/Proj_Coconut_Utility => ./pkg
