## openshift-cso-info

A Python script that provides additional info on security advisories reported by the Red Hat Quay Container Security Operator (CSO)

### Getting started

#### Install Container Security Operator
Ensure that the Container Security Operator is installed on OpenShift:
```
$ cat << EOF | oc create -f - 
oc create 
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/container-security-operator.openshift-operators: ""
  name: container-security-operator
  namespace: openshift-operators
spec:
  channel: stable-3.10
  installPlanApproval: Automatic
  name: container-security-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  startingCSV: container-security-operator.v3.10.1
EOF
```

#### Install crane
Install [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/README.md) for your distro:
```
$ VERSION=$(curl -s "https://api.github.com/repos/google/go-containerregistry/releases/latest" | jq -r '.tag_name')
$ OS=Linux
ARCH=x86_64
curl -sL "https://github.com/google/go-containerregistry/releases/download/${VERSION}/go-containerregistry_${OS}_${ARCH}.tar.gz" > go-containerregistry.tar.gz
tar -zxvf go-containerregistry.tar.gz -C /usr/local/bin/ crane
```

#### Configure crane
Grab your OpenShift pull-secret from the [OpenShift Cluster Manager](https://console.redhat.com/openshift/install/pull-secret) and add it to the local config:
```
$ mv pull-secret.txt ${XDG_RUNTIME_DIR}/containers/auth.json
```
Test out `crane` access to OpenShift images:
```
$ crane config quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:ec80bde6ca18c4de0a3b959128c62db27ed2206db1acdfaf80f2e77665ab3d3f
```

#### Create a virtual environment and install dependencies
```
virtualenv ~/cso-env
source ~/cso-env/bin/activate
pip3 install -r requirements.txt
```

#### Run cso-info
With `crane` setup and configured and the Container Security Operator installed, you can run `cso-info`:
```
$ python cso-info.py
```