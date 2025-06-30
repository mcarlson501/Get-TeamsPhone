# Get-TeamsPhoneToolkit
Get-TeamsPhoneToolkit
A community-driven collection of interactive PowerShell scripts, tools, and resources designed to simplify and accelerate the deployment and migration to Microsoft Teams Phone.

Author: Matthew Carlson (Teams Phone Cloud Solutions Architect, Microsoft)

About The Project
The goal of the Get-TeamsPhoneToolkit is to bridge the gap between official Microsoft Learn documentation and real-world execution. While the official documentation provides the "what," this toolkit provides the "how"—in the form of curated, interactive, and security-conscious script applications.

This project is a work in progress, geared towards Technical Admins, Microsoft 365 Engineers, and Managed Service Providers (MSPs) who want to confidently and efficiently deploy Teams Calling solutions for their organizations and customers.

Core Philosophy
Every script application in this toolkit is built with three principles in mind:

Security First: Features like Read-Only mode, action confirmations, and detailed logging are built-in to prevent accidental changes and provide a clear audit trail.

User-Friendliness: Interactive menus, guided walkthroughs, and clear instructions make complex processes manageable.

Real-World Execution: Scripts are designed to handle bulk operations and common administrative scenarios, moving beyond one-off commands.

Getting Started
To use a script from this toolkit:

Navigate to the specific folder for the tool you wish to use (e.g., Shared-Calling-Deployment).

Download the .ps1 script file.

Right-click the file, go to Properties, and select the Unblock checkbox at the bottom if it appears.

Open the script in a PowerShell console or the PowerShell ISE.

Run the script and follow the on-screen interactive prompts.

Script Apps in the Toolkit
This section will grow as new tools are added to the collection.

1. Shared Calling Deployment Tool
Description: An interactive application that guides an administrator through the end-to-end process of configuring Shared Calling for Microsoft Teams Phone.

Features:

Guided Walkthrough: Step-by-step process that follows the official Microsoft Learn documentation.

Live & Read-Only Modes: Choose to execute commands directly against your M365 tenant or run in a safe, read-only mode that only generates a deployment script for review.

Bulk Processing: Uses CSV files to easily manage large numbers of users for enabling voice, assigning policies, and configuring extensions.

Audit Logging: Automatically generates a timestamped log of every command executed or generated.

Security Confirmations: Requires explicit confirmation before making any changes in Live Mode.

Status: Available

Contributing
This is a community project, and contributions are welcome! If you have ideas for a new script, a feature enhancement, or you've found a bug, please feel free to open an issue in the "Issues" tab of this repository.

Disclaimer
The scripts and resources in this repository are provided as-is. While they are built with best practices in mind, you should always test them in a non-production or development environment before running them against a live production tenant. The author and contributors are not responsible for any unintended consequences or issues that may arise from their use.
