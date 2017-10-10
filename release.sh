#!/bin/bash

if [ -n "$(git status -s)" ]; then
    echo Client is not up-to-date.
    echo To fetch a clean client, run
    echo rm -rf /tmp/release-client
    echo mkdir /tmp/release-client
    echo cd /tmp/
    echo git clone git@github.com:OWASP/url-classifier.git release-client
    echo cd release-client/
    exit -1
fi

set -e

echo Existing tags
git tag --list

export LAST_VERSION="$(git tag --list --sort=taggerdate | tail -1)"
echo
echo Last version is "$LAST_VERSION"

export NEXT_VERSION="$(echo "$LAST_VERSION" | perl -pe 's/(\d+)$/$1 + 1/e')"

read -e -p "New Version [$NEXT_VERSION]: " NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    export NEW_VERSION="$NEXT_VERSION"
fi

export NEW_VERSION="$(echo "$NEW_VERSION" | perl -pe 's/^(?=\d)/v/')"

(echo $NEW_VERSION | egrep -q '^v\d+[.]\d+[.]\d+$') \
    || (
    echo "Version '$NEW_VERSION' is not a semver tag like 'v1.0.0'."
    exit -1)

# Update the pom with the new version.
perl -e 'my $version = $ENV{NEW_VERSION};' \
     -e '$version =~ s/^v//;' \
     -i.bak -pe \
     'unless ($fv) {
        $fv  = 1 if s|<version>[^<]*</|<version>$version</|;
      }' \
     pom.xml

echo Rewrote POM
git diff pom.xml
echo


# Update the version in the docs.
perl -e 'my $version = $ENV{NEW_VERSION};' \
     -e '$version =~ s/^v//;' \
     -i.bak -pe \
     's|(javadoc.io/org.owasp/url/)[\d.]+/|$1$version/|g' \
     README.md

echo Rewrote README.md
git diff README.md
echo


# Dry run
mvn clean source:jar javadoc:jar verify -DperformRelease=true \
    || (
    if [ -S "${GPG_AGENT_INFO%%:*}" ]; then
        echo Make sure you are set up to sign artifacts.
        echo Maybe run
        echo 'eval $(gpg-agent --daemon --log-file /tmp/gpg.log --write-env-file ~/.gnupg/gpg-agent.env --pinentry-program /usr/local/bin/pinentry-mac)'
        echo "echo hello world | gpg2 -e -r $(git config user.email)"
    fi
    exit -1
)
echo "Release $NEW_VERSION" > .commit_msg.txt


# Commit and tag the release
git commit -a -t .commit_msg.txt  # Commit the changed POM
git tag -m "Release $NEW_VERSION" -s "$NEW_VERSION"  # Tag the release
git push origin "$NEW_VERSION"


# Actually deploy
mvn clean source:jar javadoc:jar verify deploy:deploy -DperformRelease=true

# Merge the POM and doc updates back into master
git push origin master



echo '1. Go to oss.sonatype.org'
echo '2. Look under staging repositories for one named orgowasp-...'
echo '3. Close it.'
echo '4. Refresh until it is marked "Closed".'
echo '5. Check that its OK.'
echo '6. Release it.'
exit 0
