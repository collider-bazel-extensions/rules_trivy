"""Writes a minimal jar (a zip, fixed timestamps) holding one Maven
pom.properties: enough for Trivy to identify the artifact and version.
Usage: make_jar.py <pom.properties> <group> <artifact> <out.jar>"""
import sys
import zipfile

pom, group, artifact, out = sys.argv[1:]
with zipfile.ZipFile(out, "w") as z:
    for name, data in [
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ("META-INF/maven/{}/{}/pom.properties".format(group, artifact), open(pom, "rb").read()),
    ]:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        z.writestr(info, data)
