add_executable(BurnerNetExamples
    main.cpp
    01_basic_usage.cpp
    02_zero_trust_pipeline.cpp
    04_custom_security_policy.cpp
    05_bootstrap_runtime.cpp
)

target_link_libraries(BurnerNetExamples PRIVATE BurnerNet::BurnerNet)
burner_apply_example_warnings(BurnerNetExamples)
burnernet_configure_runtime(BurnerNetExamples)

set_target_properties(BurnerNetExamples PROPERTIES FOLDER "Examples")
