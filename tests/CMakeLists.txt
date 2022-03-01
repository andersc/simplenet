find_package (Threads REQUIRED)

if(MSVC)
  # Force to always compile with W4
  IF(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  ELSE()
    string(APPEND CMAKE_CXX_FLAGS " /W4")
  ENDIF()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
  # Update if necessary
  string(APPEND CMAKE_CXX_FLAGS " -Wall -Wno-long-long -pedantic")
endif()

set(WINSOCK_LIBRARIES)
if(WIN32)
  set(WINSOCK_LIBRARIES wsock32 ws2_32 Iphlpapi)
endif()

foreach(d client_server_udp endpoint error_handler loopback_tcp loopback_udp simple )
  add_subdirectory(${d})
  set_target_properties(${d}_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
  target_link_libraries(${d}_test PRIVATE ${OPENSSL_LIBRARIES} ${WINSOCK_LIBRARIES} Threads::Threads)
  add_test(NAME test:${d}_test COMMAND $<TARGET_FILE:${d}_test>)
  set_tests_properties(test:${d}_test PROPERTIES TIMEOUT 5)
endforeach()


