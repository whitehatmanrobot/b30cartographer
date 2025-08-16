#pragma once

/**
 * @file crc.h
 * @brief A comprehensive, header-only C++ library for calculating CRC (Cyclic Redundancy Check) checksums.
 * @version 3.0.0
 * @author Jules (AI Software Engineer)
 *
 * @details
 * Cyclic Redundancy Check (CRC) is an error-detecting code commonly used in digital networks
 * and storage devices to detect accidental changes to raw data. This library provides
 * high-performance, table-driven implementations for many popular CRC algorithms.
 *
 * A CRC is defined by its parameters:
 * - **Width**: The number of bits in the CRC value (e.g., 8, 16, 32, 64).
 * - **Polynomial**: The generator polynomial that defines the algorithm.
 * - **Initial Value**: The starting value of the CRC register.
 * - **Final XOR Value**: A value to XOR with the final CRC register value.
 * - **Reflect Input**: Whether to reflect the bits of each input byte.
 * - **Reflect Output**: Whether to reflect the bits of the final CRC value before XORing.
 *
 * This library supports the following CRC standards:
 * - **CRC-8/DALLAS**: Used in 1-Wire bus systems.
 * - **CRC-16/MODBUS**: Standard for Modbus protocol.
 * - **CRC-16/CCITT-FALSE**: A common 16-bit CRC variant.
 * - **CRC-32 (IEEE 802.3)**: The most common 32-bit CRC, used in Ethernet, PNG, etc.
 * - **CRC-32C (Castagnoli)**: Used in iSCSI, SCTP, Btrfs. Optimized for hardware.
 * - **CRC-64/ECMA-182**: A 64-bit CRC used in file formats and storage.
 *
 * For each algorithm, the library provides two interfaces:
 * 1. A simple function call for one-shot calculation (e.g., `crc::crc32(data)`).
 * 2. A calculator class for incremental (streaming) calculations (e.g., `crc::Crc32Calculator`).
 *
 * All implementations are header-only and use pre-computed lookup tables for high performance.
 */

#include <array>
#include <cstdint>
#include <numeric>
#include <string_view>
#include <vector>
#include <type_traits>

namespace crc {

    namespace detail {

        /**
         * @brief A template class to generate CRC lookup tables at compile time.
         * This version handles both reflected and non-reflected algorithms.
         * @tparam T The integral type for the CRC value (e.g., uint8_t, uint16_t, uint32_t, uint64_t).
         * @tparam reflect If true, the table is generated for a reflected algorithm.
         */
        template <typename T, bool reflect>
        class CrcTable {
        public:
            constexpr CrcTable(T polynomial) noexcept : table_{} {
                constexpr int bits = sizeof(T) * 8;
                for (int i = 0; i < 256; ++i) {
                    T crc = static_cast<T>(i);
                    if constexpr (reflect) {
                         crc = static_cast<T>(i);
                    } else {
                         crc <<= (bits - 8);
                    }

                    for (int j = 0; j < 8; ++j) {
                        if constexpr (reflect) {
                            if (crc & 1) {
                                crc = (crc >> 1) ^ polynomial;
                            } else {
                                crc >>= 1;
                            }
                        } else {
                            if (crc & (static_cast<T>(1) << (bits - 1))) {
                                crc = (crc << 1) ^ polynomial;
                            } else {
                                crc <<= 1;
                            }
                        }
                    }
                    table_[static_cast<size_t>(i)] = crc;
                }
            }

            constexpr T operator[](size_t index) const noexcept {
                return table_[index];
            }

        private:
            std::array<T, 256> table_;
        };

        // Pre-computed tables for various CRC standards.
        // Note: Reflected algorithms use a reversed polynomial.
        constexpr auto crc8_dallas_table = CrcTable<uint8_t, true>(0x8C); // Poly=0x31, reversed
        constexpr auto crc16_modbus_table = CrcTable<uint16_t, true>(0xA001); // Poly=0x8005, reversed
        constexpr auto crc16_ccitt_table = CrcTable<uint16_t, false>(0x1021); // Poly=0x1021, normal
        constexpr auto crc32_table = CrcTable<uint32_t, true>(0xEDB88320); // Poly=0x04C11DB7, reversed
        constexpr auto crc32c_table = CrcTable<uint32_t, true>(0x82F63B78); // Poly=0x1EDC6F41, reversed
        constexpr auto crc64_ecma_table = CrcTable<uint64_t, true>(0xC96C5795D7870F42); // Poly=0x42F0E1EBA9EA3693, reversed

        /**
         * @brief Reflects the bits of an integral value.
         * @tparam T The integral type.
         * @param value The value to reflect.
         * @return The bit-reflected value.
         */
        template <typename T>
        constexpr T reflect_bits(T value) noexcept {
            T reflection = 0;
            constexpr int bits = sizeof(T) * 8;
            for (int i = 0; i < bits; ++i) {
                if (value & 1) {
                    reflection |= (static_cast<T>(1) << (bits - 1 - i));
                }
                value >>= 1;
            }
            return reflection;
        }

    } // namespace detail

    /**
     * @brief A generic, reusable CRC calculator class.
     *
     * This class template provides a flexible way to calculate any CRC by specifying
     * its parameters. It supports incremental (streaming) updates.
     *
     * @tparam T The integral type for the CRC register (uint8_t, uint16_t, etc.).
     * @tparam Polynomial The generator polynomial.
     * @tparam InitialValue The initial value of the CRC register.
     * @tparam FinalXorValue The value to XOR with the final CRC result.
     * @tparam ReflectInput Specifies whether to reflect each input byte.
     * @tparam ReflectOutput Specifies whether to reflect the final CRC result.
     */
    template<typename T, T Polynomial, T InitialValue, T FinalXorValue, bool ReflectInput, bool ReflectOutput>
    class CrcCalculator {
    public:
        using value_type = T;

        CrcCalculator() noexcept : crc_register_(InitialValue) {}

        /**
         * @brief Updates the CRC value with a block of data.
         * @param data A string_view pointing to the data.
         */
        void update(std::string_view data) noexcept {
            for (const unsigned char c : data) {
                if constexpr (ReflectInput) {
                    crc_register_ = (crc_register_ >> 8) ^ table_[(crc_register_ & 0xFF) ^ c];
                } else {
                    crc_register_ = (crc_register_ << 8) ^ table_[(crc_register_ >> (sizeof(T) * 8 - 8)) ^ c];
                }
            }
        }

        /**
         * @brief Updates the CRC value with a vector of bytes.
         * @param data A vector of bytes.
         */
        void update(const std::vector<uint8_t>& data) noexcept {
            update(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
        }

        /**
         * @brief Finalizes the calculation and returns the CRC checksum.
         * @return The calculated CRC value.
         */
        [[nodiscard]] T final() const noexcept {
            if constexpr (ReflectOutput) {
                return detail::reflect_bits(crc_register_) ^ FinalXorValue;
            } else {
                return crc_register_ ^ FinalXorValue;
            }
        }

        /**
         * @brief Resets the calculator to its initial state.
         */
        void reset() noexcept {
            crc_register_ = InitialValue;
        }

    private:
        // The lookup table is selected based on the CRC type and reflection parameter.
        static constexpr auto table_ = detail::CrcTable<T, ReflectInput>(Polynomial);
        T crc_register_;
    };

    // == Typedefs for Common CRC Calculator Classes ==
    using Crc8DallasCalculator = CrcCalculator<uint8_t, 0x8C, 0x00, 0x00, true, true>;
    using Crc16ModbusCalculator = CrcCalculator<uint16_t, 0xA001, 0xFFFF, 0x0000, true, true>;
    using Crc16CcittFalseCalculator = CrcCalculator<uint16_t, 0x1021, 0xFFFF, 0x0000, false, false>;
    using Crc32Calculator = CrcCalculator<uint32_t, 0xEDB88320, 0xFFFFFFFF, 0xFFFFFFFF, true, true>;
    using Crc32cCalculator = CrcCalculator<uint32_t, 0x82F63B78, 0xFFFFFFFF, 0xFFFFFFFF, true, true>;
    using Crc64EcmaCalculator = CrcCalculator<uint64_t, 0xC96C5795D7870F42, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true, true>;


    // == One-shot CRC Functions ==

    /**
     * @brief Calculates the CRC-8/DALLAS checksum.
     * @param data The data to be checksummed.
     * @return The 8-bit CRC value.
     */
    inline uint8_t crc8_dallas(std::string_view data) noexcept {
        Crc8DallasCalculator calc;
        calc.update(data);
        return calc.final();
    }
    inline uint8_t crc8_dallas(const std::vector<uint8_t>& data) noexcept {
        return crc8_dallas(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    /**
     * @brief Calculates the CRC-16/MODBUS checksum.
     * @param data The data to be checksummed.
     * @return The 16-bit CRC value.
     */
    inline uint16_t crc16_modbus(std::string_view data) noexcept {
        Crc16ModbusCalculator calc;
        calc.update(data);
        return calc.final();
    }
    inline uint16_t crc16_modbus(const std::vector<uint8_t>& data) noexcept {
        return crc16_modbus(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }
    // Alias for backward compatibility
    inline uint16_t crc16(std::string_view data) noexcept { return crc16_modbus(data); }
    inline uint16_t crc16(const std::vector<uint8_t>& data) noexcept { return crc16_modbus(data); }

    /**
     * @brief Calculates the CRC-16/CCITT-FALSE checksum.
     * @param data The data to be checksummed.
     * @return The 16-bit CRC value.
     */
    inline uint16_t crc16_ccitt_false(std::string_view data) noexcept {
        Crc16CcittFalseCalculator calc;
        calc.update(data);
        return calc.final();
    }
    inline uint16_t crc16_ccitt_false(const std::vector<uint8_t>& data) noexcept {
        return crc16_ccitt_false(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    /**
     * @brief Calculates the CRC-32 (IEEE 802.3) checksum.
     * @param data The data to be checksummed.
     * @return The 32-bit CRC value.
     */
    inline uint32_t crc32(std::string_view data) noexcept {
        Crc32Calculator calc;
        calc.update(data);
        return calc.final();
    }
    inline uint32_t crc32(const std::vector<uint8_t>& data) noexcept {
        return crc32(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    /**
     * @brief Calculates the CRC-32C (Castagnoli) checksum.
     * @param data The data to be checksummed.
     * @return The 32-bit CRC-32C value.
     */
    inline uint32_t crc32c(std::string_view data) noexcept {
        Crc32cCalculator calc;
        calc.update(data);
        return calc.final();
    }
    inline uint32_t crc32c(const std::vector<uint8_t>& data) noexcept {
        return crc32c(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }

} // namespace crc

// This namespace is kept for compatibility with the original obfuscator.cpp code
namespace crc_extended {

    /**
     * @brief Calculates the CRC-64 (ECMA-182) checksum for a block of data.
     * @param data The data to be checksummed.
     * @return The 64-bit CRC value.
     */
    inline uint64_t crc64_ecma(std::string_view data) noexcept {
        crc::Crc64EcmaCalculator calc;
        calc.update(data);
        return calc.final();
    }

    /**
     * @brief Calculates the CRC-64 (ECMA-182) checksum for a block of data.
     * @param data The data to be checksummed.
     * @return The 64-bit CRC value.
     */
    inline uint64_t crc64_ecma(const std::vector<uint8_t>& data) noexcept {
        return crc64_ecma(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    // Deprecated alias for backward compatibility.
    [[deprecated("Use crc64_ecma instead")]]
    inline uint64_t crc64(std::string_view data) noexcept {
        return crc64_ecma(data);
    }

    [[deprecated("Use crc64_ecma instead")]]
    inline uint64_t crc64(const std::vector<uint8_t>& data) noexcept {
        return crc64_ecma(data);
    }

} // namespace crc_extended
