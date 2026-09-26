@echo off
rem Uses the installed daemon and the current account's fixed .ssh identity.
tcsd %*
exit /b %errorlevel%
