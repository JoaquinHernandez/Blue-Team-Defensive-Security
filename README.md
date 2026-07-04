# Ransomware Canary File Deployer

## Overview
A defensive security monitoring utility that drops hidden "canary" files into sensitive target directories. It utilizes low-level operating system file system events to watch for unauthorized modifications, rewrites, or deletions typical of ransomware encryption sweeps.

## Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
