@ECHO OFF

pushd %~dp0

REM Command file for Sphinx documentation

if "%SPHINXBUILD%" == "" (
	set SPHINXBUILD=sphinx-build
)
set SOURCEDIR=.\
set BUILDDIR=.\_build
set HTMLDIR=.\_build\html
set REMOTE=gh-pages-remote
set REMOTELINK=https://github.com/arcsector/PAWSS

if "%1" == "" goto help

%SPHINXBUILD% >NUL 2>NUL
if errorlevel 9009 (
	echo.
	echo.The 'sphinx-build' command was not found. Make sure you have Sphinx
	echo.installed, then set the SPHINXBUILD environment variable to point
	echo.to the full path of the 'sphinx-build' executable. Alternatively you
	echo.may add the Sphinx directory to PATH.
	echo.
	echo.If you don't have Sphinx installed, grab it from
	echo.http://sphinx-doc.org/
	exit /b 1
)

%SPHINXBUILD% -M %1 %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

REM Push to github pages

cd %HTMLDIR%
IF EXIST .git ( 
echo 
) ELSE (
git init
git remote add %REMOTE% %REMOTELINK%
git pull %REMOTE% gh-pages
)
git checkout -b gh-pages
git add -A
git commit
git push %REMOTE% gh-pages

goto end

:help
%SPHINXBUILD% -M help %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

:end
popd