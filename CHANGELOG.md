# Changelog

All notable changes to Moltbook Agent Manager will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-01-31

### Added
- Open source release preparation
- Comprehensive logging system with file output (`~/.moltbook_logs/`)
- Full diagnostics tab with system info, API health, and troubleshooting
- API health monitoring with success rates and response times
- "Open on Moltbook" buttons as workaround for comment API issues
- Topic picker for AI-generated posts (9 categories)
- Smart error dialogs with workaround suggestions
- Security status display in diagnostics
- Debug info copy-to-clipboard feature
- CONTRIBUTING.md, CHANGELOG.md, proper LICENSE

### Changed
- Improved AI post generation with topic variety (no more repetitive content)
- Enhanced error handling with specific exception types
- Converted debug prints to proper logging
- Better documentation and code comments

### Fixed
- Bare `except:` clauses replaced with specific exceptions
- Debug output cleaned up for production use

## [3.0.1] - 2026-01-31

### Added
- Topic picker dropdown in Compose tab
- 9 topic categories for AI generation
- Random topic selection option

### Changed
- AI generation prompt now includes topic direction
- Higher temperature for more creative outputs
- Explicit instructions to avoid repetitive content

## [3.0.0] - 2026-01-31

### Added
- 🔧 Diagnostics tab with full system monitoring
- API health tracking (success rates, response times)
- Known issues section with workarounds
- Dependency status checker
- Security status display
- Recent errors log viewer
- Quick actions (copy debug info, clear logs, test endpoints)
- File logging to `~/.moltbook_logs/`
- "Open on Moltbook" button for comment workaround

### Changed
- Version bump to 3.0.0 for major diagnostics update

## [2.6.2] - 2026-01-31

### Added
- Multi-endpoint retry for comment creation
- Detailed API debugging output
- Comment API issue detection

### Fixed
- Legacy plaintext API key handling
- Better error messages for API failures

## [2.6.1] - 2026-01-31

### Fixed
- Security module handling of legacy plaintext keys
- Debug logging for 401 errors

## [2.6.0] - 2026-01-31

### Added
- 🔒 Three-tier API key encryption (keyring/AES/XOR)
- Secure storage module with automatic encryption
- Expand/collapse comments feature (show all comments)
- Database schema for drafts, templates, brand settings
- Default post templates
- Security status indicator in settings

### Security
- API keys now encrypted before database storage
- System keyring integration (Windows Credential Manager, macOS Keychain)
- Fallback to AES-256 encryption
- Machine-specific encryption keys

## [2.5.0] - 2026-01-31

### Added
- Edit agent dialog (modify name, description, personality)
- AI-generated reply button for comments
- Inline reply to comments from My Posts tab
- Comment notification highlighting (🔔 for others' comments)

### Changed
- Improved My Posts display with embedded comments
- Better comment threading UI

## [2.4.0] - 2026-01-30

### Added
- My Posts tab with comment viewing
- Quick reply functionality
- Comment count statistics

## [2.3.0] - 2026-01-30

### Added
- Feed browser tab
- Auto-engage feature
- Post scheduling system

## [2.2.0] - 2026-01-30

### Added
- Activity log with export to CSV
- AI activity analysis
- Agent statistics dashboard

## [2.1.0] - 2026-01-30

### Added
- Dark/Light theme toggle
- Settings panel with OpenAI API key
- Import/Export agents as JSON

## [2.0.0] - 2026-01-30

### Added
- Complete UI redesign with CustomTkinter
- Multi-agent management
- AI-powered post generation
- Real-time preview in compose

## [1.0.0] - 2026-01-29

### Added
- Initial release
- Basic agent registration
- Manual post creation
- Simple activity tracking
