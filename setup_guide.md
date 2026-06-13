# Codex Project Setup & Configuration Guide

This guide outlines the essential pre-requisites and setup steps required before importing your project into Codex. Ensure all criteria are strictly met to guarantee a seamless development workflow and full functionality of the advanced skillsets.

---

## 🛠️ Pre-Import Checklists

### 1. Codex Environment & Version
* **Core IDE:** Ensure you are using the official **Codex** development environment.
* **Update Status:** Verify your Codex installation is updated to the latest stable release before initializing the project import wizard.

### 2. Context Level Configuration
* **Required Setting:** **Context 7**
* **Verification Steps:**
  1. Navigate to `Settings` / `Preferences` within Codex.
  2. Locate the **AI & Context Configuration** section.
  3. Adjust the context level slider or input box to exactly **7**. 
  4. Save and apply changes. *Note: Setting this lower may restrict the model's architectural awareness, while setting it higher could cause performance overhead.*

### 3. Required Plugins & Extensions
* **Sentry Plugin:**
  * Must be fully installed and enabled before proceeding.
  * **Installation:** Search for "Sentry" in the Codex Plugin Marketplace and click **Install**.
  * **Configuration:** Ensure your Sentry DSN and organization properties are accessible so real-time error tracking mapping can bind to your workspace immediately upon project import.

---

## 🚀 Advanced Cursor Skills Integration

To maximize efficiency and take advantage of advanced automated workflows, you must incorporate the cursor skills repository patterns.

* **Reference Repository:** [Awesome Cursor Skills](https://github.com/spencerpauly/awesome-cursor-skills)
* **Requirement:** All skills detailed within the repository must be reviewed, configured, or imported into your custom Codex rulesets or workspace behaviors.

### Core Skill categories to verify:
1. **Context Navigation & Framing:** Techniques for feeding high-density structural context to the LLM.
2. **Prompt Optimization Triggers:** Pre-packaged shortcuts to generate refactored code without boilerplate regression.
3. **Automated Refactoring Workflows:** Streamlined cursor mechanics to execute complex edits across multiple files cleanly.

---

## 📥 Proceeding to Project Import

Once the above checkmarks display a green status:
1. Launch Codex.
2. Select **File > Import Project** (or **Open Workspace**).
3. Choose your project root directory.
4. Codex will index the workspace using **Context 7** bounds and pair semantic code maps with your active **Sentry Plugin** alert hooks.
