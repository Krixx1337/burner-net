add_executable(BurnerNetExamples
    main.cpp
    01_basic_usage.cpp
    02_security_audit.cpp
    03_traffic_lanes.cpp
    04_custom_security_policy.cpp
)

target_link_libraries(BurnerNetExamples PRIVATE BurnerNet::BurnerNet)
burner_apply_example_warnings(BurnerNetExamples)
burnernet_configure_runtime(BurnerNetExamples)

set_target_properties(BurnerNetExamples PROPERTIES FOLDER "Examples")
