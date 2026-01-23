Project Overview

Developed a custom SSH Honeypot in Python to simulate a vulnerable service and capture unauthorized reconnaissance and brute-force attempts. The system goes beyond simple logging by analyzing attacker behavior and generating real-time security tickets sent directly via email.
Key Features

    Behavioral Logging: Captures source IP addresses, login credentials used, and commands attempted by attackers in a simulated environment.

    Automated Alerting System: Integrated an automated email notification system that sends a detailed security "ticket" whenever an intrusion is detected.

    Threat Assessment: Categorizes incidents based on the severity of the commands executed, helping to distinguish between automated bots and targeted manual attempts.

    Reporting & Analytics: Generated comprehensive security reports summarizing attack patterns, top attacking IPs, and common credential dictionaries used in brute-force attacks.

Technologies Used

    Language: Python

    Protocols: SSH, SMTP (for email alerts)

    Security Concepts: Deception Technology, Intrusion Detection (IDS), Log Analysis

    Environment: Linux/Unix VM
