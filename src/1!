#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include <stack>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <cmath>
#include <cstdint>

class VirtualMachine {
private:
    std::map<std::string, uint64_t> registers = {
        // 64-bit registers
        {"rax", 0}, {"rbx", 0}, {"rcx", 0}, {"rdx", 0},
        {"rsi", 0}, {"rdi", 0}, {"rbp", 0}, {"rsp", 0},
        {"r8", 0}, {"r9", 0}, {"r10", 0}, {"r11", 0},
        {"r12", 0}, {"r13", 0}, {"r14", 0}, {"r15", 0},
        
        // 32-bit subregisters
        {"eax", 0}, {"ebx", 0}, {"ecx", 0}, {"edx", 0},
        {"esi", 0}, {"edi", 0}, {"ebp", 0}, {"esp", 0},
        
        // 16-bit subregisters
        {"ax", 0}, {"bx", 0}, {"cx", 0}, {"dx", 0},
        {"si", 0}, {"di", 0}, {"bp", 0}, {"sp", 0},
        
        // 8-bit subregisters
        {"al", 0}, {"bl", 0}, {"cl", 0}, {"dl", 0},
        {"sil", 0}, {"dil", 0}, {"bpl", 0}, {"spl", 0},
        {"ah", 0}, {"bh", 0}, {"ch", 0}, {"dh", 0},
        
        // Special registers
        {"rip", 0}, {"flags", 0}
    };
    
    std::map<std::string, size_t> labels;
    std::vector<std::string> program_lines;
    std::stack<uint64_t> data_stack;
    std::stack<size_t> call_stack;
    std::map<uint64_t, uint64_t> memory;
    bool running = true;

    // Flag bits
    enum Flags {
        FLAG_CF = 1 << 0,      // Carry Flag
        FLAG_PF = 1 << 2,      // Parity Flag
        FLAG_AF = 1 << 4,      // Auxiliary Carry Flag
        FLAG_ZF = 1 << 6,      // Zero Flag
        FLAG_SF = 1 << 7,      // Sign Flag
        FLAG_TF = 1 << 8,      // Trap Flag
        FLAG_IF = 1 << 9,      // Interrupt Enable Flag
        FLAG_DF = 1 << 10,     // Direction Flag
        FLAG_OF = 1 << 11      // Overflow Flag
    };

public:
    void load_program(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filename);
        }

        std::string line;
        size_t line_number = 0;

        while (std::getline(file, line)) {
            ++line_number;

            // Remove comments
            size_t comment_pos = line.find(';');
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }

            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);

            if (line.empty()) continue;

            // Handle labels
            if (line.back() == ':') {
                std::string label = line.substr(0, line.size() - 1);
                labels[label] = program_lines.size();
                continue;
            }

            program_lines.push_back(line);
        }
    }

    void execute_program(const std::string& entry_point = "main") {
        if (labels.find(entry_point) == labels.end()) {
            throw std::runtime_error("Entry point '" + entry_point + "' not found");
        }

        registers["rip"] = static_cast<uint64_t>(labels[entry_point]);
        running = true;

        while (running && registers["rip"] < static_cast<uint64_t>(program_lines.size())) {
            auto line = program_lines[registers["rip"]];
            if (line.empty()) {
                registers["rip"]++;
                continue;
            }

            auto tokens = tokenize(line);
            if (tokens.empty()) {
                registers["rip"]++;
                continue;
            }
            
            execute_instruction(tokens);
        }
    }

    void dump_state() const {
        std::cout << "\n=== VM STATE DUMP ===\n";
        std::cout << "Registers:\n";
        for (const auto& reg : registers) {
            std::cout << "  " << reg.first << ": 0x" << std::hex << reg.second << std::dec;
            if (reg.first == "flags") {
                std::cout << " [";
                if (reg.second & FLAG_CF) std::cout << "CF ";
                if (reg.second & FLAG_PF) std::cout << "PF ";
                if (reg.second & FLAG_AF) std::cout << "AF ";
                if (reg.second & FLAG_ZF) std::cout << "ZF ";
                if (reg.second & FLAG_SF) std::cout << "SF ";
                if (reg.second & FLAG_TF) std::cout << "TF ";
                if (reg.second & FLAG_IF) std::cout << "IF ";
                if (reg.second & FLAG_DF) std::cout << "DF ";
                if (reg.second & FLAG_OF) std::cout << "OF";
                std::cout << "]";
            }
            std::cout << "\n";
        }

        std::cout << "\nStack (top first):\n";
        auto stack_copy = data_stack;
        while (!stack_copy.empty()) {
            std::cout << "  0x" << std::hex << stack_copy.top() << std::dec << "\n";
            stack_copy.pop();
        }
        
        std::cout << "\nMemory (non-zero values):\n";
        for (const auto& mem : memory) {
            if (mem.second != 0) {
                std::cout << "  [0x" << std::hex << mem.first << "] = 0x" << mem.second << std::dec << "\n";
            }
        }
        
        std::cout << "===================\n\n";
    }

private:
    std::vector<std::string> tokenize(const std::string& line) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream token_stream(line);

        while (token_stream >> token) {
            // Remove commas and make lowercase
            token.erase(std::remove(token.begin(), token.end(), ','), token.end());
            std::transform(token.begin(), token.end(), token.begin(), ::tolower);
            if (!token.empty()) {
                tokens.push_back(token);
            }
        }   

        return tokens;
    }

    void set_flag(Flags flag, bool set) {
        if (set) {
            registers["flags"] |= flag;
        } else {
            registers["flags"] &= ~flag;
        }
    }

    bool get_flag(Flags flag) const {
        return (registers.at("flags") & flag) != 0;
    }

    uint64_t get_value(const std::string& operand) {
        if (registers.count(operand)) {
            // Handle subregisters
            if (operand == "eax") return registers["rax"] & 0xFFFFFFFF;
            else if (operand == "ebx") return registers["rbx"] & 0xFFFFFFFF;
            else if (operand == "ecx") return registers["rcx"] & 0xFFFFFFFF;
            else if (operand == "edx") return registers["rdx"] & 0xFFFFFFFF;
            else if (operand == "esi") return registers["rsi"] & 0xFFFFFFFF;
            else if (operand == "edi") return registers["rdi"] & 0xFFFFFFFF;
            else if (operand == "ebp") return registers["rbp"] & 0xFFFFFFFF;
            else if (operand == "esp") return registers["rsp"] & 0xFFFFFFFF;
            
            else if (operand == "ax") return registers["rax"] & 0xFFFF;
            else if (operand == "bx") return registers["rbx"] & 0xFFFF;
            else if (operand == "cx") return registers["rcx"] & 0xFFFF;
            else if (operand == "dx") return registers["rdx"] & 0xFFFF;
            else if (operand == "si") return registers["rsi"] & 0xFFFF;
            else if (operand == "di") return registers["rdi"] & 0xFFFF;
            else if (operand == "bp") return registers["rbp"] & 0xFFFF;
            else if (operand == "sp") return registers["rsp"] & 0xFFFF;
            
            else if (operand == "al") return registers["rax"] & 0xFF;
            else if (operand == "bl") return registers["rbx"] & 0xFF;
            else if (operand == "cl") return registers["rcx"] & 0xFF;
            else if (operand == "dl") return registers["rdx"] & 0xFF;
            else if (operand == "sil") return registers["rsi"] & 0xFF;
            else if (operand == "dil") return registers["rdi"] & 0xFF;
            else if (operand == "bpl") return registers["rbp"] & 0xFF;
            else if (operand == "spl") return registers["rsp"] & 0xFF;
            
            else if (operand == "ah") return (registers["rax"] >> 8) & 0xFF;
            else if (operand == "bh") return (registers["rbx"] >> 8) & 0xFF;
            else if (operand == "ch") return (registers["rcx"] >> 8) & 0xFF;
            else if (operand == "dh") return (registers["rdx"] >> 8) & 0xFF;
            
            return registers.at(operand);
        } else if (operand[0] == '[' && operand.back() == ']') {
            // Memory access
            std::string addr = operand.substr(1, operand.size() - 2);
            uint64_t address = get_value(addr);
            return memory[address];
        } else if (operand == "stack") {
            if (data_stack.empty()) throw std::runtime_error("Stack underflow");
            return data_stack.top();
        } else {
            // Try to parse as immediate value
            try {
                if (operand.size() > 2 && operand[0] == '0' && operand[1] == 'x') {
                    return std::stoull(operand.substr(2), nullptr, 16);
                }
                return std::stoull(operand, nullptr, 0);
            } catch (...) {
                throw std::runtime_error("Invalid operand: " + operand);
            }
        }
    }

    void set_value(const std::string& dest, uint64_t value) {
        if (registers.count(dest)) {
            // Handle subregisters
            if (dest == "eax") { registers["rax"] = (registers["rax"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "ebx") { registers["rbx"] = (registers["rbx"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "ecx") { registers["rcx"] = (registers["rcx"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "edx") { registers["rdx"] = (registers["rdx"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "esi") { registers["rsi"] = (registers["rsi"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "edi") { registers["rdi"] = (registers["rdi"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "ebp") { registers["rbp"] = (registers["rbp"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            else if (dest == "esp") { registers["rsp"] = (registers["rsp"] & 0xFFFFFFFF00000000) | (value & 0xFFFFFFFF); }
            
            else if (dest == "ax") { registers["rax"] = (registers["rax"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "bx") { registers["rbx"] = (registers["rbx"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "cx") { registers["rcx"] = (registers["rcx"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "dx") { registers["rdx"] = (registers["rdx"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "si") { registers["rsi"] = (registers["rsi"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "di") { registers["rdi"] = (registers["rdi"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "bp") { registers["rbp"] = (registers["rbp"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            else if (dest == "sp") { registers["rsp"] = (registers["rsp"] & 0xFFFFFFFFFFFF0000) | (value & 0xFFFF); }
            
            else if (dest == "al") { registers["rax"] = (registers["rax"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "bl") { registers["rbx"] = (registers["rbx"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "cl") { registers["rcx"] = (registers["rcx"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "dl") { registers["rdx"] = (registers["rdx"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "sil") { registers["rsi"] = (registers["rsi"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "dil") { registers["rdi"] = (registers["rdi"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "bpl") { registers["rbp"] = (registers["rbp"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            else if (dest == "spl") { registers["rsp"] = (registers["rsp"] & 0xFFFFFFFFFFFFFF00) | (value & 0xFF); }
            
            else if (dest == "ah") { registers["rax"] = (registers["rax"] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8); }
            else if (dest == "bh") { registers["rbx"] = (registers["rbx"] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8); }
            else if (dest == "ch") { registers["rcx"] = (registers["rcx"] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8); }
            else if (dest == "dh") { registers["rdx"] = (registers["rdx"] & 0xFFFFFFFFFFFF00FF) | ((value & 0xFF) << 8); }
            
            else {
                registers[dest] = value;
            }
        } else if (dest[0] == '[' && dest.back() == ']') {
            // Memory access
            std::string addr = dest.substr(1, dest.size() - 2);
            uint64_t address = get_value(addr);
            memory[address] = value;
        } else if (dest == "stack") {
            data_stack.push(value);
        } else {
            throw std::runtime_error("Invalid destination: " + dest);
        }
    }

    void execute_instruction(const std::vector<std::string>& tokens) {
        if (tokens.empty()) return;

        const std::string& command = tokens[0];

        try {
            // Data movement
            if (command == "mov") {
                if (tokens.size() < 3) throw std::runtime_error("MOV requires 2 operands");
                uint64_t value = get_value(tokens[2]);
                set_value(tokens[1], value);
                registers["rip"]++;
            }
            else if (command == "push") {
                if (tokens.size() < 2) throw std::runtime_error("PUSH requires 1 operand");
                data_stack.push(get_value(tokens[1]));
                registers["rsp"] -= 8;
                registers["rip"]++;
            }
            else if (command == "pop") {
                if (data_stack.empty()) throw std::runtime_error("Stack underflow");
                if (tokens.size() > 1) {
                    set_value(tokens[1], data_stack.top());
                }
                data_stack.pop();
                registers["rsp"] += 8;
                registers["rip"]++;
            }
            else if (command == "lea") {
                if (tokens.size() < 3) throw std::runtime_error("LEA requires 2 operands");
                if (tokens[2][0] == '[' && tokens[2].back() == ']') {
                    std::string addr = tokens[2].substr(1, tokens[2].size() - 2);
                    set_value(tokens[1], get_value(addr));
                } else {
                    throw std::runtime_error("LEA requires memory operand");
                }
                registers["rip"]++;
            }

            // Arithmetic
            else if (command == "add") {
                if (tokens.size() < 3) throw std::runtime_error("ADD requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a + b;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_CF, result < a);
                set_flag(FLAG_OF, ((a ^ ~b) & (a ^ result)) >> 63);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, ((a ^ b ^ result) & 0x10) != 0);
                
                registers["rip"]++;
            }
            else if (command == "sub") {
                if (tokens.size() < 3) throw std::runtime_error("SUB requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a - b;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_CF, b > a);
                set_flag(FLAG_OF, ((a ^ b) & (a ^ result)) >> 63);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, ((a ^ b ^ result) & 0x10) != 0);
                
                registers["rip"]++;
            }
            else if (command == "inc") {
                if (tokens.size() < 2) throw std::runtime_error("INC requires 1 operand");
                uint64_t a = get_value(tokens[1]);
                uint64_t result = a + 1;
                set_value(tokens[1], result);
                
                // Set flags (CF not affected)
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_OF, a == 0x7FFFFFFFFFFFFFFF);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, (result & 0xF) == 0);
                
                registers["rip"]++;
            }
            else if (command == "dec") {
                if (tokens.size() < 2) throw std::runtime_error("DEC requires 1 operand");
                uint64_t a = get_value(tokens[1]);
                uint64_t result = a - 1;
                set_value(tokens[1], result);
                
                // Set flags (CF not affected)
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_OF, a == 0x8000000000000000);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, (result & 0xF) == 0xF);
                
                registers["rip"]++;
            }
            else if (command == "mul") {
                if (tokens.size() < 2) throw std::runtime_error("MUL requires 1 operand");
                uint64_t a = registers["rax"];
                uint64_t b = get_value(tokens[1]);
                uint64_t result_low = a * b;
                uint64_t result_high = (a * b) >> 64;
                
                registers["rax"] = result_low;
                registers["rdx"] = result_high;
                
                // Set flags
                set_flag(FLAG_CF, result_high != 0);
                set_flag(FLAG_OF, result_high != 0);
                // ZF, SF, PF, AF are undefined
                
                registers["rip"]++;
            }
            else if (command == "imul") {
                if (tokens.size() < 2) throw std::runtime_error("IMUL requires 1 operand");
                int64_t a = static_cast<int64_t>(registers["rax"]);
                int64_t b = static_cast<int64_t>(get_value(tokens[1]));
                int64_t result = a * b;
                
                registers["rax"] = static_cast<uint64_t>(result);
                registers["rdx"] = static_cast<uint64_t>(result >> 63); // Sign extension
                
                // Set flags
                set_flag(FLAG_CF, registers["rdx"] != 0);
                set_flag(FLAG_OF, registers["rdx"] != 0);
                // ZF, SF, PF, AF are undefined
                
                registers["rip"]++;
            }
            else if (command == "div") {
                if (tokens.size() < 2) throw std::runtime_error("DIV requires 1 operand");
                uint64_t divisor = get_value(tokens[1]);
                if (divisor == 0) throw std::runtime_error("Division by zero");
                
                uint64_t dividend_low = registers["rax"];
                uint64_t dividend_high = registers["rdx"];
                uint64_t dividend = (dividend_high << 32) | (dividend_low >> 32);
                
                uint64_t quotient = dividend / divisor;
                uint64_t remainder = dividend % divisor;
                
                if (quotient > 0xFFFFFFFF) {
                    throw std::runtime_error("Division overflow");
                }
                
                registers["rax"] = quotient;
                registers["rdx"] = remainder;
                
                // Flags are undefined for DIV
                registers["rip"]++;
            }
            else if (command == "idiv") {
                if (tokens.size() < 2) throw std::runtime_error("IDIV requires 1 operand");
                int64_t divisor = static_cast<int64_t>(get_value(tokens[1]));
                if (divisor == 0) throw std::runtime_error("Division by zero");
                
                int64_t dividend = (static_cast<int64_t>(registers["rdx"]) << 32) | 
                                  (registers["rax"] >> 32);
                int64_t quotient = dividend / divisor;
                int64_t remainder = dividend % divisor;
                
                if (quotient > 0x7FFFFFFF || quotient < -0x80000000) {
                    throw std::runtime_error("Division overflow");
                }
                
                registers["rax"] = static_cast<uint64_t>(quotient);
                registers["rdx"] = static_cast<uint64_t>(remainder);
                
                // Flags are undefined for IDIV
                registers["rip"]++;
            }
            else if (command == "neg") {
                if (tokens.size() < 2) throw std::runtime_error("NEG requires 1 operand");
                uint64_t a = get_value(tokens[1]);
                uint64_t result = -a;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_CF, a != 0);
                set_flag(FLAG_OF, a == 0x8000000000000000);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, (result & 0xF) != 0);
                
                registers["rip"]++;
            }

            // Bitwise operations
            else if (command == "and") {
                if (tokens.size() < 3) throw std::runtime_error("AND requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a & b;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, false);
                set_flag(FLAG_OF, false);
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "or") {
                if (tokens.size() < 3) throw std::runtime_error("OR requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a | b;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, false);
                set_flag(FLAG_OF, false);
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "xor") {
                if (tokens.size() < 3) throw std::runtime_error("XOR requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a ^ b;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, false);
                set_flag(FLAG_OF, false);
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "not") {
                if (tokens.size() < 2) throw std::runtime_error("NOT requires 1 operand");
                uint64_t result = ~get_value(tokens[1]);
                set_value(tokens[1], result);
                // Flags are not affected by NOT
                registers["rip"]++;
            }
            else if (command == "shl") {
                if (tokens.size() < 3) throw std::runtime_error("SHL requires 2 operands");
                uint64_t value = get_value(tokens[1]);
                uint64_t shift = get_value(tokens[2]);
                uint64_t result = value << shift;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, shift != 0 && ((value >> (64 - shift)) & 1));
                // OF is set if the sign bit changes (only for shift=1)
                if (shift == 1) {
                    set_flag(FLAG_OF, ((value ^ result) >> 63) & 1);
                }
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "shr") {
                if (tokens.size() < 3) throw std::runtime_error("SHR requires 2 operands");
                uint64_t value = get_value(tokens[1]);
                uint64_t shift = get_value(tokens[2]);
                uint64_t result = value >> shift;
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, shift != 0 && ((value >> (shift - 1)) & 1));
                // OF is set to the MSB of the original value (only for shift=1)
                if (shift == 1) {
                    set_flag(FLAG_OF, (value >> 63) & 1);
                }
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "sar") {
                if (tokens.size() < 3) throw std::runtime_error("SAR requires 2 operands");
                int64_t value = static_cast<int64_t>(get_value(tokens[1]));
                uint64_t shift = get_value(tokens[2]);
                int64_t result = value >> shift;
                set_value(tokens[1], static_cast<uint64_t>(result));
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(static_cast<uint64_t>(result) & 0xFF));
                set_flag(FLAG_CF, shift != 0 && ((value >> (shift - 1)) & 1));
                // OF is cleared for SAR
                set_flag(FLAG_OF, false);
                // AF is undefined
                
                registers["rip"]++;
            }
            else if (command == "rol") {
                if (tokens.size() < 3) throw std::runtime_error("ROL requires 2 operands");
                uint64_t value = get_value(tokens[1]);
                uint64_t shift = get_value(tokens[2]) % 64;
                uint64_t result = (value << shift) | (value >> (64 - shift));
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_CF, (result >> 63) & 1);
                // OF is set if the MSB changes (only for shift=1)
                if (shift == 1) {
                    set_flag(FLAG_OF, ((value ^ result) >> 63) & 1);
                }
                // ZF, SF, PF, AF are undefined
                
                registers["rip"]++;
            }
            else if (command == "ror") {
                if (tokens.size() < 3) throw std::runtime_error("ROR requires 2 operands");
                uint64_t value = get_value(tokens[1]);
                uint64_t shift = get_value(tokens[2]) % 64;
                uint64_t result = (value >> shift) | (value << (64 - shift));
                set_value(tokens[1], result);
                
                // Set flags
                set_flag(FLAG_CF, (result >> 63) & 1);
                // OF is set to the XOR of the two MSBs (only for shift=1)
                if (shift == 1) {
                    set_flag(FLAG_OF, ((value ^ result) >> 62) & 1);
                }
                // ZF, SF, PF, AF are undefined
                
                registers["rip"]++;
            }

            // Comparison
            else if (command == "cmp") {
                if (tokens.size() < 3) throw std::runtime_error("CMP requires 2 operands");
                uint64_t a = get_value(tokens[1]);
                uint64_t b = get_value(tokens[2]);
                uint64_t result = a - b;
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_CF, b > a);
                set_flag(FLAG_OF, ((a ^ b) & (a ^ result)) >> 63);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_AF, ((a ^ b ^ result) & 0x10) != 0);
                
                registers["rip"]++;
            }
            else if (command == "test") {
                if (tokens.size() < 3) throw std::runtime_error("TEST requires 2 operands");
                uint64_t result = get_value(tokens[1]) & get_value(tokens[2]);
                
                // Set flags
                set_flag(FLAG_ZF, result == 0);
                set_flag(FLAG_SF, (result >> 63) & 1);
                set_flag(FLAG_PF, __builtin_parityll(result & 0xFF));
                set_flag(FLAG_CF, false);
                set_flag(FLAG_OF, false);
                // AF is undefined
                
                registers["rip"]++;
            }

            // Control flow
            else if (command == "jmp") {
                if (tokens.size() < 2) throw std::runtime_error("JMP requires 1 operand");
                registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
            }
            else if (command == "je" || command == "jz") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                if (get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jne" || command == "jnz") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                if (!get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "ja") {
                if (tokens.size() < 2) throw std::runtime_error("JA requires 1 operand");
                if (!get_flag(FLAG_CF) && !get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jae") {
                if (tokens.size() < 2) throw std::runtime_error("JAE requires 1 operand");
                if (!get_flag(FLAG_CF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jb") {
                if (tokens.size() < 2) throw std::runtime_error("JB requires 1 operand");
                if (get_flag(FLAG_CF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jbe") {
                if (tokens.size() < 2) throw std::runtime_error("JBE requires 1 operand");
                if (get_flag(FLAG_CF) || get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jg") {
                if (tokens.size() < 2) throw std::runtime_error("JG requires 1 operand");
                if (!get_flag(FLAG_ZF) && (get_flag(FLAG_SF) == get_flag(FLAG_OF))) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jge") {
                if (tokens.size() < 2) throw std::runtime_error("JGE requires 1 operand");
                if (get_flag(FLAG_SF) == get_flag(FLAG_OF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jl") {
                if (tokens.size() < 2) throw std::runtime_error("JL requires 1 operand");
                if (get_flag(FLAG_SF) != get_flag(FLAG_OF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jle") {
                if (tokens.size() < 2) throw std::runtime_error("JLE requires 1 operand");
                if (get_flag(FLAG_ZF) || (get_flag(FLAG_SF) != get_flag(FLAG_OF))) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "js") {
                if (tokens.size() < 2) throw std::runtime_error("JS requires 1 operand");
                if (get_flag(FLAG_SF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jns") {
                if (tokens.size() < 2) throw std::runtime_error("JNS requires 1 operand");
                if (!get_flag(FLAG_SF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jo") {
                if (tokens.size() < 2) throw std::runtime_error("JO requires 1 operand");
                if (get_flag(FLAG_OF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jno") {
                if (tokens.size() < 2) throw std::runtime_error("JNO requires 1 operand");
                if (!get_flag(FLAG_OF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jp" || command == "jpe") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                if (get_flag(FLAG_PF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jnp" || command == "jpo") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                if (!get_flag(FLAG_PF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "jcxz" || command == "jecxz" || command == "jrcxz") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                uint64_t value = 0;
                if (command == "jcxz") value = registers["rcx"] & 0xFFFF;
                else if (command == "jecxz") value = registers["rcx"] & 0xFFFFFFFF;
                else value = registers["rcx"];
                
                if (value == 0) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "loop") {
                if (tokens.size() < 2) throw std::runtime_error("LOOP requires 1 operand");
                registers["rcx"]--;
                if (registers["rcx"] != 0) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "loope" || command == "loopz") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                registers["rcx"]--;
                if (registers["rcx"] != 0 && get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "loopne" || command == "loopnz") {
                if (tokens.size() < 2) throw std::runtime_error(command + " requires 1 operand");
                registers["rcx"]--;
                if (registers["rcx"] != 0 && !get_flag(FLAG_ZF)) {
                    registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
                } else {
                    registers["rip"]++;
                }
            }
            else if (command == "call") {
                if (tokens.size() < 2) throw std::runtime_error("CALL requires 1 operand");
                call_stack.push(registers["rip"] + 1);
                registers["rip"] = static_cast<uint64_t>(labels.at(tokens[1]));
            }
            else if (command == "ret") {
                if (call_stack.empty()) throw std::runtime_error("RET called with empty call stack");
                registers["rip"] = static_cast<uint64_t>(call_stack.top());
                call_stack.pop();
            }

            // I/O operations
            else if (command == "in") {
                if (tokens.size() < 2) throw std::runtime_error("IN requires 1 operand");
                uint64_t input;
                std::cin >> input;
                set_value(tokens[1], input);
                registers["rip"]++;
            }
            else if (command == "out") {
                if (tokens.size() < 2) throw std::runtime_error("OUT requires 1 operand");
                std::cout << get_value(tokens[1]);
                registers["rip"]++;
            }
            else if (command == "out_char") {
                if (tokens.size() < 2) throw std::runtime_error("OUT_CHAR requires 1 operand");
                std::cout << static_cast<char>(get_value(tokens[1]));
                registers["rip"]++;
            }

            /* else if (command == "out_str") {
                for (size_t i = 1; i < tokens.size(); ++i) {
                    std::cout << static_cast<char>(get_value(tokens[i]));
                }
                registers["rip"]++;
            }
            */

            else if (command == "out_str") {
               for (size_t i = 1; i < tokens.size(); ++i) {
                  if (tokens[i][0] == '"' && tokens[i].back() == '"') {
                     // String literal
                     std::string str = tokens[i].substr(1, tokens[i].size() - 2);
                     std::cout << str;
                  } else {
                     // Numeric value
                     std::cout << static_cast<char>(get_value(tokens[i]));
                  }  
               }
               registers["rip"]++;
            }     

            else if (command == "out_str_lit") {
                // Output string literal (everything after the command)
                size_t pos = program_lines[registers["rip"]].find(command);
                std::string str = program_lines[registers["rip"]].substr(pos + command.length());
                // Remove leading whitespace and quotes if present
                str.erase(0, str.find_first_not_of(" \t"));
                if (str.front() == '"' && str.back() == '"') {
                    str = str.substr(1, str.size() - 2);
                }
                std::cout << str;
                registers["rip"]++;
            }

            // System
            else if (command == "nop") {
                registers["rip"]++;
            }
            else if (command == "halt") {
                running = false;
            }
            else if (command == "dump") {
                dump_state();
                registers["rip"]++;
            }
            else if (command == "clear") {
                #ifdef _WIN32
                system("cls");
                #else
                system("clear");
                #endif
                registers["rip"]++;
            }

            // Memory operations
            else if (command == "load") {
                if (tokens.size() < 3) throw std::runtime_error("LOAD requires 2 operands");
                uint64_t address = get_value(tokens[2]);
                set_value(tokens[1], memory[address]);
                registers["rip"]++;
            }
            else if (command == "store") {
                if (tokens.size() < 3) throw std::runtime_error("STORE requires 2 operands");
                uint64_t address = get_value(tokens[1]);
                uint64_t value = get_value(tokens[2]);
                memory[address] = value;
                registers["rip"]++;
            }
            else {
                throw std::runtime_error("Unknown command: " + command);
            }
        }
        catch (const std::exception& e) {
            throw std::runtime_error("Error executing '" + command + "' at line " + 
                                   std::to_string(registers["rip"] + 1) + ": " + e.what());
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file.asm> [entry_point]" << std::endl;
        return 1;
    }

    try {
        VirtualMachine vm;
        vm.load_program(argv[1]);
        
        std::string entry_point = (argc > 2) ? argv[2] : "main";
        vm.execute_program(entry_point);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
