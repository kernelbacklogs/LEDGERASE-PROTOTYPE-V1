#include "cli.hpp"
#include "ledgerase/ledgerase.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
    ledgerase::CliApplication app;
    return app.run(argc, argv);
}