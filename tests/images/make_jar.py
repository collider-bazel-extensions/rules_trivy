"""Writes a minimal jar (a zip, fixed timestamps) holding one Maven
pom.properties: enough for Trivy to identify the artifact and version;
with a pom.xml too, Trivy reads the licences it declares.
Usage: make_jar.py <pom.properties> <group> <artifact> <out.jar> [<pom.xml>]"""
import sys
import zipfile

pom, group, artifact, out = sys.argv[1:5]
entries = [
    ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
    ("META-INF/maven/{}/{}/pom.properties".format(group, artifact), open(pom, "rb").read()),
]
if len(sys.argv) > 5:
    entries.append(("META-INF/maven/{}/{}/pom.xml".format(group, artifact), open(sys.argv[5], "rb").read()))
with zipfile.ZipFile(out, "w") as z:
    for name, data in entries:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        z.writestr(info, data)
