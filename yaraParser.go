package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/VirusTotal/gyp"
	"github.com/google/gopacket"
)

// Create the suricataRules folder if it does not exist
func createYaraRulesDir() {
	if _, err := os.Stat(yaraRulesDir); os.IsNotExist(err) {
		err := os.Mkdir(yaraRulesDir, os.ModePerm)
		if err != nil {
			fmt.Printf("Error creating directory: %s\n", err)
			os.Exit(1)
		}
	}
}

func (a *App) LoadYaraRules(filename string, data []byte) bool {
	println("File Name", filename)
	println("File Data", data)
	// Create or ensure suricataRules directory
	createYaraRulesDir()

	println("Dir created.")
	// Save the file
	if _, err := os.Stat(yaraRulesDir); os.IsNotExist(err) {
		err := os.Mkdir(yaraRulesDir, os.ModePerm)
		if err != nil {
			fmt.Errorf("error creating directory: %s", err)
			return false
		}
	}
	println("File Saved.")

	// Save the file
	filePath := filepath.Join(yaraRulesDir, filename)
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Errorf("error saving file: %s", err)
		return false
	}
	println("Data Copied: ", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Errorf("failed to open YARA rules file: %w", err)
		return false
	}
	defer file.Close()

	// Parse the YARA rules using the io.Reader
	rules, err := gyp.Parse(file)
	if err == nil {
		yaraRules = rules.Rules
		println("Yara Rules Len: ", len(yaraRules))
		return len(yaraRules) > 0
	} else {
		fmt.Errorf("failed to parse YARA rules: %w", err)
		return false
	}

	return false
}

// removeSpacesAndNewlines removes all spaces and newlines from a string
func removeSpacesAndNewlines(s string) string {
	// Remove spaces and newlines
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "") // For carriage returns
	// print("Cleaned", s)
	return s
}

// contains checks if the first string contains the second string after removing spaces and newlines
func containsstr(str1, str2 string) bool {
	// Remove spaces and newlines
	str1 = removeSpacesAndNewlines(str1)
	str2 = removeSpacesAndNewlines(str2)

	// Check if str1 contains str2
	return strings.Contains(str1, str2)
}

func removeChars(input string) string {
	// Create a replacer to remove the specified characters
	replacer := strings.NewReplacer(
		"\"", "",
		"{", "",
		"}", "",
		" ", "",
	)
	// Replace the characters in the input string
	result := replacer.Replace(input)
	return result
}

func removeBraceAndSpaces(input string) string {
	// Create a replacer to remove the specified characters
	replacer := strings.NewReplacer(
		"{", "",
		"}", "",
		" ", "",
	)
	// Replace the characters in the input string
	result := replacer.Replace(input)
	return result
}

func checkForYaraMatch(packet gopacket.Packet, packInfo PacketInfo) PacketInfo {
	p_str := packet.String()
	p_hex := packet.Data()
	// check if packet string or hex match yara rules
	for _, rule := range yaraRules {
		for _, str := range rule.Strings {
			s_t := strings.Split(str.String(), "=")
			if len(s_t) < 2 {
				return packInfo
			}

			s := strings.Trim(s_t[1], " ")
			// if startsAndEndsWithBraces(s) {
			// 	fmt.Printf("############Yara Rule Hex: %s\n", s)
			// } else {
			// 	fmt.Printf("**********Yara Rule String: %s\n", s)
			// }

			if startsAndEndsWithBraces(s) && containsHex(p_hex, removeBraceAndSpaces(s)) {
				fmt.Printf("%s Packet Hex contains %s\n", packInfo.Timestamp, s)
				var alert AlertMessage
				alert.AlertMessage = rule.Identifier + " Matched"
				alert.Timestamp = packInfo.Timestamp
				alert.AlertType = 2
				packInfo.YaraAlert = append(packInfo.YaraAlert, alert)
				if !packInfo.HasAlert {
					packInfo.HasAlert = true
				}
			} else {
				// s := strings.Split(str.String(), "=")[1]
				s = removeChars(s)

				// println("Checking for yara string: ", s)
				if containsstr(p_str, s) {
					fmt.Printf("%s Packet String contains %s\n", packInfo.Timestamp, s)
					var alert AlertMessage
					alert.AlertMessage = rule.Identifier + " Matched"
					alert.Timestamp = packInfo.Timestamp
					alert.AlertType = 2
					packInfo.YaraAlert = append(packInfo.YaraAlert, alert)
					if !packInfo.HasAlert {
						packInfo.HasAlert = true
					}
				}
			}
		}
	}
	return packInfo
}

// checkByteSequence checks if the sequence represented by the hex string exists in the byte slice
func containsHex(data []byte, hexString string) bool {
	// Decode the hex string to a byte slice
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return false
	}

	// Check if the hex byte sequence exists in the data byte slice
	return containsSequence(data, hexBytes)
}

// containsSequence checks if a sequence of bytes exists in a byte slice
func containsSequence(data []byte, seq []byte) bool {
	// Use a simple loop to check for the sequence
	for i := 0; i <= len(data)-len(seq); i++ {
		if string(data[i:i+len(seq)]) == string(seq) {
			return true
		}
	}
	return false
}

func startsAndEndsWithBraces(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}
