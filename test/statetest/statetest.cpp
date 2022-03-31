
#include <gtest/gtest.h>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

class StateTest : public testing::Test
{
    fs::path m_json_test_file;

public:
    explicit StateTest(fs::path json_test_file) : m_json_test_file{std::move(json_test_file)} {}
    void TestBody() override { std::cout << m_json_test_file << "\n"; }
};

int main(int argc, char* argv[])
{
    testing::InitGoogleTest(&argc, argv);

    if (argc != 2)
        return -1;

    const fs::path root_test_dir{argv[1]};
    for (const auto& dir_entry : fs::recursive_directory_iterator{root_test_dir})
    {
        const auto& p = dir_entry.path();
        if (dir_entry.is_regular_file() && p.extension() == ".json")
        {
            const auto d = fs::relative(p, root_test_dir);
            testing::RegisterTest(d.parent_path().c_str(), d.stem().c_str(), nullptr, nullptr,
                p.c_str(), 0, [p]() -> testing::Test* { return new StateTest(p); });
        }
    }

    return RUN_ALL_TESTS();
}
