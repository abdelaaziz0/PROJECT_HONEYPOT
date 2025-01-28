# Advanced Honeypot System

⚠️ **DISCLAIMER** ⚠️

This project is for **EDUCATIONAL PURPOSES ONLY**. The author and contributors:
- Are NOT responsible for any malicious use of this code
- Do NOT endorse using this system for malicious purposes
- Are NOT liable for any damages caused by the misuse of this software
- Strongly recommend using this ONLY in controlled, authorized environments

By using this software, you agree to:
- Use it solely for educational and research purposes
- Comply with all applicable laws and regulations
- Take full responsibility for your own actions
- Not use it for any malicious or harmful activities

**If you do not agree with these terms, do not use this software.**

---

This project implements an advanced honeypot system designed to attract, monitor, and analyze attacker behaviors. It includes multiple components for simulating vulnerable services, capturing network traffic, and analyzing attack patterns.

## Features

- SSH and HTTP service simulation
- Real-time packet capture and analysis
- Automated response system
- Machine learning-based anomaly detection
- Email alerting system
- IP blocking capabilities
- Comprehensive data analysis and visualization

## Components

### Core Services
- `ssh_honeypot.py`: SSH service simulator
- `http_honeypot.py`: HTTP service simulator with a fake admin panel
- `packet_capture.py`: Network traffic capture using Scapy

### Analysis & Response
- `data_analysis.py`: Statistical analysis and visualization of captured data
- `ml_detection.py`: Machine learning model for anomaly detection
- `email_alert.py`: Email notification system for suspicious activities
- `ip_blocker.py`: Automatic blocking of malicious IPs

### Testing Tools
- `honeypot_attacker.py`: Basic attack simulation tool
- `adv_att.py`: Advanced attack simulation with multiple attack vectors

## Prerequisites

```bash
# System packages
sudo apt update
sudo apt install python3 python3-pip libpcap-dev sqlite3

# Python packages
pip3 install -r requirements.txt
```

## Configuration

1. Database Setup:
   - The system uses SQLite for data storage
   - Database files are created automatically when running the services

2. Email Alerts:
   - Edit `email_alert.py` to configure your SMTP settings:
   ```python
   SMTP_SERVER = 'smtp.example.com'
   SMTP_PORT = 587
   SMTP_USER = 'your_email@example.com'
   SMTP_PASSWORD = 'your_password'
   TO_EMAIL = 'admin@example.com'
   ```

3. Network Configuration:
   - Default SSH honeypot port: 2222
   - Default HTTP honeypot port: 8080
   - Edit the respective service files to change ports if needed

## Usage

1. Start the core services:
```bash
# Start SSH honeypot
python3 ssh_honeypot.py

# Start HTTP honeypot
python3 http_honeypot.py

# Start packet capture
python3 packet_capture.py
```

2. Start the monitoring and response systems:
```bash
# Start anomaly detection
python3 ml_detection.py

# Start IP blocker (requires root privileges)
sudo python3 ip_blocker.py

# Start email alerts
python3 email_alert.py
```

3. Run data analysis:
```bash
python3 data_analysis.py
```

## Data Analysis

The system generates several visualizations:
- Daily attack patterns
- Top attacking IP addresses
- Protocol distribution
- Request type distribution
- Anomaly detection results

Graphs are saved in PNG format in the project directory.

## Security Considerations

- Deploy the honeypot in an isolated environment
- Use a dedicated network interface
- Regularly monitor system resources
- Keep all components updated
- Review logs periodically

## Development

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Testing

For testing purposes, two attack simulation scripts are provided:
- `honeypot_attacker.py`: Basic attacks
- `adv_att.py`: Advanced attack scenarios

**Warning**: Only use these scripts in controlled environments.

## License

This project is licensed under the MIT License, which means:

### What you can do:
- ✅ Use the code commercially
- ✅ Modify the code
- ✅ Distribute the code
- ✅ Use it privately

### What you must do:
- 📝 Include the copyright notice
- 📝 Include the MIT License text

See the [LICENSE](LICENSE) file for the full license text.

### Third-Party Licenses
This project uses several third-party libraries that are distributed under their own licenses:
- Scapy (GPL v2)
- SQLite (Public Domain)
- Pandas (BSD 3-Clause)
- Scikit-learn (BSD 3-Clause)

Make sure to comply with all license terms when using this software.

## Author

BELKHAIR Abdelaaziz  
Contact: abelkhair002@bordeaux-inp.fr

## Acknowledgments

- Cowrie Project for SSH honeypot inspiration
- Dionaea Project for protocol handling examples
- Honeyd Project for architecture design patterns
