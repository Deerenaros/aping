cmake_minimum_required(VERSION 3.2)

project(aping)
set(SOURCE main.cpp)

if(WIN32)
	include_directories(win)
	list(APPEND SOURCE win/ping.cpp)
elseif(UNIX)
	list(APPEND SOURCE lin/ping.cpp)
endif()

add_executable(aping ${SOURCE})

if(WIN32)
	# smthn goes wrong
	link_directories("C:/Program Files (x86)/Windows Kits/10/Lib/10.0.10240.0/um/x86")
	target_link_libraries(aping Wbemuuid.lib WS2_32.lib)
endif(WIN32)

add_compile_options(-std=c++11)
