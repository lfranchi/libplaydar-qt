add_subdirectory( JsonQt )

project(libplaydar-qt)
cmake_minimum_required(VERSION 2.6)
find_package(Qt4 REQUIRED)

include_directories(
                    ${QT_INCLUDES} ${CMAKE_CURRENT_BINARY_DIR} )



set(libplaydar-qt_SRCS 
#        libplaydar-qt.cpp 
#        main.cpp
    PlaydarAuthRequest.cpp
    PlaydarCometRequest.cpp
    PlaydarConnection.cpp
    PlaydarHostsModel.cpp
    PlaydarPollingRequest.cpp
    PlaydarRosterRequest.cpp
    PlaydarTagCloudModel.cpp
    PlaylistModel.cpp
    
)


qt4_automoc(${libplaydar-qt_SRCS})
add_library(libplaydar-qt ${libplaydar-qt_SRCS})
target_link_libraries( libplaydar-qt 
                       ${QT_QTCORE_LIBRARY}
                       JsonQt )
