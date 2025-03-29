# C Web Application Firewall (C-WAF)

![C-WAF](https://img.shields.io/badge/C-WAF-blue.svg)

## 🚀 Overview
C-WAF is a lightweight Web Application Firewall (WAF) built in C, designed to filter and monitor HTTP traffic. It utilizes configurable rule sets to enhance security and mitigate potential threats.

## 📂 Project Structure
```
C-WAF/
│── config-rule.conf   # Configuration file for rules
│── main.c             # Main source code file
│── README.md          # Documentation
```

## 🛠️ Features
- Rule-based filtering via `config-rule.conf`
- Multi-threaded support for handling multiple requests (`-lpthread`)
- Static binary compilation for portability

## 🔧 Installation
### 📥 Clone the Repository
```sh
git clone https://github.com/Kaveen-Adithya/C-WAF.git
cd C-WAF
```

### 🏗️ Install Dependencies
Ensure you have GCC installed on your system. If not, install it using:
- **Debian/Ubuntu**:
  ```sh
  sudo apt update && sudo apt install gcc
  ```
- **CentOS/RHEL**:
  ```sh
  sudo yum install gcc
  ```
- **Windows (MinGW)**:
  Download and install [MinGW](https://osdn.net/projects/mingw/releases/).

### 🔨 Compile the Source Code
```sh
gcc -o waf main.c -lpthread -static
```

## 🚀 Running C-WAF
```sh
./waf
```
By default, C-WAF will use `config-rule.conf` to apply filtering rules.

## 📜 License
This project is licensed under the MIT License.

## 📞 Contact
For any issues or contributions, feel free to open a GitHub issue!

---
🎯 **Developed with ❤️ by [Kaveen-Adithya](https://github.com/Kaveen-Adithya)**

