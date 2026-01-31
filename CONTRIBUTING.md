# Contributing to Moltbook Agent Manager

First off, thank you for considering contributing to Moltbook Agent Manager! 🦞

## Code of Conduct

Be respectful and constructive. We're all here to build cool stuff for the AI agent community.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

1. **Clear title** describing the issue
2. **Steps to reproduce** the behavior
3. **Expected behavior** vs actual behavior
4. **Screenshots** if applicable
5. **Debug info** - Use the Diagnostics tab → "Copy Debug Info" button
6. **OS and Python version**

### Suggesting Features

Feature requests are welcome! Please:

1. Check if the feature already exists or is planned
2. Describe the feature and its use case
3. Explain why it would benefit the community

### Pull Requests

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/moltbook-agent-manager.git
cd moltbook-agent-manager

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Install optional security packages
pip install keyring cryptography

# Run the app
python moltbook_agent_manager.py
```

## Code Style

### Python Style
- Follow PEP 8
- Use meaningful variable names
- Add docstrings to functions and classes
- Use type hints where practical

### Logging
- Use `logger.debug()`, `logger.info()`, `logger.warning()`, `logger.error()`
- Don't use `print()` for production code
- Never log API keys or sensitive data

### Error Handling
- Use specific exception types (not bare `except:`)
- Provide helpful error messages to users
- Log errors for debugging

### SQL
- Always use parameterized queries (`?` placeholders)
- Never concatenate user input into SQL strings

### Example:
```python
# Good
def fetch_agent(agent_id: int) -> Optional[Dict]:
    """Fetch an agent by ID from the database."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        result = c.fetchone()
        conn.close()
        return dict(result) if result else None
    except sqlite3.Error as e:
        logger.error(f"Database error fetching agent {agent_id}: {e}")
        return None

# Bad
def fetch_agent(id):
    try:
        c.execute(f"SELECT * FROM agents WHERE id = {id}")  # SQL injection!
        return c.fetchone()
    except:  # Bare except!
        print("error")  # Using print!
```

## Testing

Before submitting a PR:

1. **Manual testing** - Run the app and test your changes
2. **Check all tabs** - Dashboard, Compose, My Posts, Activity, Schedule, Feed, Diagnostics
3. **Test edge cases** - Empty states, errors, invalid input
4. **Check the console** - No unexpected errors or warnings

## Project Structure

```
moltbook-agent-manager/
├── moltbook_agent_manager.py  # Main application (single file)
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
├── LICENSE                    # MIT License
├── CHANGELOG.md              # Version history
├── CONTRIBUTING.md           # This file
├── .gitignore                # Git ignore rules
└── pyproject.toml            # Python packaging config
```

## Key Components

The app is a single-file application with these main sections:

1. **Security Module** (~lines 35-300) - API key encryption
2. **API Health Monitor** (~lines 50-200) - Request tracking
3. **MoltbookAPI Class** (~lines 600-800) - API client
4. **AIAnalyzer Class** (~lines 820-1000) - OpenAI integration
5. **Database Functions** (~lines 500-600) - SQLite operations
6. **MoltbookManagerApp Class** (~lines 1000+) - Main UI

## Questions?

Open an issue with the "question" label or reach out to the maintainers.

## Recognition

Contributors will be acknowledged in the README and release notes. Thank you for helping make Moltbook Agent Manager better! 🦞
