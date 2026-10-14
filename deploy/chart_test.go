// Package deploy tests the Helm chart by rendering it with helm.
package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.uber.org/goleak"
	"sigs.k8s.io/yaml"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type object struct {
	Kind     string          `json:"kind"`
	Metadata json.RawMessage `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
	Data     map[string]string
}

type securityContext struct {
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	RunAsUser                *int64 `json:"runAsUser"`
	RunAsGroup               *int64 `json:"runAsGroup"`
	FSGroup                  *int64 `json:"fsGroup"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	Privileged               *bool  `json:"privileged"`
	ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem"`
	Capabilities             *struct {
		Add  []string `json:"add"`
		Drop []string `json:"drop"`
	} `json:"capabilities"`
	SeccompProfile *struct {
		Type string `json:"type"`
	} `json:"seccompProfile"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	SecurityContext *securityContext `json:"securityContext"`
	Ports           []struct {
		ContainerPort int `json:"containerPort"`
		HostPort      int `json:"hostPort"`
	} `json:"ports"`
	Resources struct {
		Limits map[string]string `json:"limits"`
	} `json:"resources"`
}

type podSpec struct {
	HostNetwork                  bool             `json:"hostNetwork"`
	HostPID                      bool             `json:"hostPID"`
	HostIPC                      bool             `json:"hostIPC"`
	AutomountServiceAccountToken *bool            `json:"automountServiceAccountToken"`
	SecurityContext              *securityContext `json:"securityContext"`
	Containers                   []container      `json:"containers"`
	InitContainers               []container      `json:"initContainers"`
	Volumes                      []struct {
		Name     string          `json:"name"`
		HostPath json.RawMessage `json:"hostPath"`
		Secret   *struct {
			DefaultMode *int `json:"defaultMode"`
		} `json:"secret"`
	} `json:"volumes"`
}

type deploymentSpec struct {
	Template struct {
		Spec podSpec `json:"spec"`
	} `json:"template"`
}

type peer struct {
	IPBlock *struct {
		CIDR   string   `json:"cidr"`
		Except []string `json:"except"`
	} `json:"ipBlock"`
	NamespaceSelector json.RawMessage `json:"namespaceSelector"`
	PodSelector       json.RawMessage `json:"podSelector"`
}

type port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type networkPolicySpec struct {
	PolicyTypes []string `json:"policyTypes"`
	Ingress     []struct {
		From  []peer `json:"from"`
		Ports []port `json:"ports"`
	} `json:"ingress"`
	Egress []struct {
		To    []peer `json:"to"`
		Ports []port `json:"ports"`
	} `json:"egress"`
}

func render(t *testing.T, set ...string) (map[string]object, error) {
	t.Helper()
	args := []string{"template", "test", "helm/relay", "-f", "helm/relay/ci/default-values.yaml"}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), "helm", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	objects := map[string]object{}
	for doc := range strings.SplitSeq(string(out), "\n---") {
		if strings.TrimSpace(strings.TrimPrefix(doc, "---")) == "" {
			continue
		}
		js, err := yaml.YAMLToJSON([]byte(doc))
		if err != nil {
			t.Fatalf("%v\n%s", err, doc)
		}
		var o object
		if err := json.Unmarshal(js, &o); err != nil {
			t.Fatal(err)
		}
		if o.Kind == "" {
			continue
		}
		if _, dup := objects[o.Kind]; dup {
			t.Fatalf("two objects of kind %s", o.Kind)
		}
		objects[o.Kind] = o
	}
	return objects, nil
}

func mustRender(t *testing.T, set ...string) map[string]object {
	t.Helper()
	objects, err := render(t, set...)
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			t.Fatalf("helm template: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	return objects
}

func spec[T any](t *testing.T, o object) T {
	t.Helper()
	var s T
	if err := json.Unmarshal(o.Spec, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func isTrue(b *bool) bool  { return b != nil && *b }
func isFalse(b *bool) bool { return b != nil && !*b }

// TestChartPodSecurity checks the pod against the restricted Pod Security Standard and the plan:
// non-root UID 65532, read-only root, no capabilities, RuntimeDefault seccomp, no host access.
func TestChartPodSecurity(t *testing.T) {
	t.Parallel()
	objects := mustRender(t, "issuerCA.configMapName=issuer-ca", "config.dpopNonces.lifetime=2m", "nonceKey.secretName=nonce-key")
	d, ok := objects["Deployment"]
	if !ok {
		t.Fatal("no Deployment")
	}
	pod := spec[deploymentSpec](t, d).Template.Spec
	if pod.HostNetwork || pod.HostPID || pod.HostIPC {
		t.Error("host namespaces shared")
	}
	if !isFalse(pod.AutomountServiceAccountToken) {
		t.Error("service account token mounted")
	}
	psc := pod.SecurityContext
	if psc == nil || !isTrue(psc.RunAsNonRoot) || psc.RunAsUser == nil || *psc.RunAsUser != 65532 ||
		psc.RunAsGroup == nil || *psc.RunAsGroup != 65532 || psc.FSGroup == nil || *psc.FSGroup != 65532 {
		t.Errorf("pod securityContext %+v", psc)
	}
	if psc == nil || psc.SeccompProfile == nil || psc.SeccompProfile.Type != "RuntimeDefault" {
		t.Error("pod seccomp is not RuntimeDefault")
	}
	for _, v := range pod.Volumes {
		if v.HostPath != nil {
			t.Errorf("volume %s mounts a host path", v.Name)
		}
		if v.Secret != nil && (v.Secret.DefaultMode == nil || *v.Secret.DefaultMode&0o037 != 0) {
			t.Errorf("secret volume %s is readable beyond its group", v.Name)
		}
	}
	containers := slices.Concat(pod.Containers, pod.InitContainers)
	if len(containers) == 0 {
		t.Fatal("no containers")
	}
	for _, c := range containers {
		sc := c.SecurityContext
		if sc == nil {
			t.Fatalf("%s: no securityContext", c.Name)
		}
		if !isFalse(sc.AllowPrivilegeEscalation) || !isFalse(sc.Privileged) || !isTrue(sc.ReadOnlyRootFilesystem) || !isTrue(sc.RunAsNonRoot) {
			t.Errorf("%s: securityContext %+v", c.Name, sc)
		}
		if sc.Capabilities == nil || !slices.Equal(sc.Capabilities.Drop, []string{"ALL"}) || len(sc.Capabilities.Add) != 0 {
			t.Errorf("%s: capabilities not dropped", c.Name)
		}
		if sc.SeccompProfile == nil || sc.SeccompProfile.Type != "RuntimeDefault" {
			t.Errorf("%s: seccomp is not RuntimeDefault", c.Name)
		}
		for _, p := range c.Ports {
			if p.HostPort != 0 {
				t.Errorf("%s: host port %d", c.Name, p.HostPort)
			}
		}
		if strings.HasSuffix(c.Image, ":latest") || !strings.Contains(c.Image, ":") && !strings.Contains(c.Image, "@sha256:") {
			t.Errorf("%s: image %q is not pinned", c.Name, c.Image)
		}
		if c.Resources.Limits["memory"] == "" {
			t.Errorf("%s: no memory limit", c.Name)
		}
	}
	if _, ok := objects["PodDisruptionBudget"]; !ok {
		t.Error("no PodDisruptionBudget")
	}
}

// TestChartNetworkPolicy checks that the relay accepts only its port and reaches only the
// authorization server, the configured prefixes and the cluster DNS.
func TestChartNetworkPolicy(t *testing.T) {
	t.Parallel()
	objects := mustRender(t, "config.egress.allow={10.0.0.0/8,192.168.10.0/24}")
	np, ok := objects["NetworkPolicy"]
	if !ok {
		t.Fatal("no NetworkPolicy")
	}
	s := spec[networkPolicySpec](t, np)
	if !slices.Contains(s.PolicyTypes, "Ingress") || !slices.Contains(s.PolicyTypes, "Egress") {
		t.Fatalf("policyTypes %v", s.PolicyTypes)
	}
	for _, in := range s.Ingress {
		if len(in.Ports) != 1 || in.Ports[0].Port != 8443 || in.Ports[0].Protocol != "TCP" {
			t.Errorf("ingress ports %+v", in.Ports)
		}
	}
	var cidrs []string
	dns := false
	for _, eg := range s.Egress {
		if len(eg.To) == 0 {
			t.Fatal("an egress rule allows every destination")
		}
		for _, p := range eg.To {
			switch {
			case p.IPBlock != nil:
				cidrs = append(cidrs, p.IPBlock.CIDR)
			case p.NamespaceSelector != nil && p.PodSelector != nil:
				dns = true
				for _, port := range eg.Ports {
					if port.Port != 53 {
						t.Errorf("DNS rule opens port %d", port.Port)
					}
				}
				if len(eg.Ports) == 0 {
					t.Error("DNS rule opens every port")
				}
			default:
				t.Errorf("egress peer %+v is broader than a CIDR or the DNS pods", p)
			}
		}
	}
	slices.Sort(cidrs)
	if want := []string{"10.0.0.0/8", "192.0.2.10/32", "192.168.10.0/24"}; !slices.Equal(cidrs, want) {
		t.Errorf("egress CIDRs %v, want %v", cidrs, want)
	}
	if !dns {
		t.Error("no DNS egress")
	}

	off := mustRender(t, "networkPolicy.dns.enabled=false")
	for _, eg := range spec[networkPolicySpec](t, off["NetworkPolicy"]).Egress {
		for _, p := range eg.To {
			if p.IPBlock == nil {
				t.Error("DNS egress present when disabled")
			}
		}
	}
}

func TestChartRendersTheRelayConfig(t *testing.T) {
	t.Parallel()
	objects := mustRender(t, "issuerCA.configMapName=issuer-ca", "config.dpopNonces.lifetime=2m", "nonceKey.secretName=nonce-key", `config.session.interval=30s`)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(objects["ConfigMap"].Data["config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"listen":         ":8443",
		"issuer":         "https://auth.example.com",
		"issuer_ca_file": "/etc/relay/issuer-ca/ca.crt",
		"dpop_nonces":    map[string]any{"lifetime": "2m", "key_file": "/etc/relay/nonce-key/key"},
		"session":        map[string]any{"interval": "30s"},
		"registration":   map[string]any{"dir": "/var/lib/relay/registration"},
	}
	for k, v := range want {
		if !reflect.DeepEqual(cfg[k], v) {
			t.Errorf("%s = %v, want %v", k, cfg[k], v)
		}
	}
	single := mustRender(t, "replicaCount=1", "config.dpopNonces.lifetime=2m")
	if strings.Contains(single["ConfigMap"].Data["config.json"], "key_file") {
		t.Error("a single replica given a nonce key file it has no Secret for")
	}
	plain := mustRender(t)
	if strings.Contains(plain["ConfigMap"].Data["config.json"], "dpop_nonces") {
		t.Error("nonces required without being configured")
	}
}

func TestChartRequiresValues(t *testing.T) {
	t.Parallel()
	for _, set := range []string{"config.dpopNonces.lifetime=2m", "config.issuer=", "tls.secretName=", "registration.secretName=", "config.egress.allow=null", "networkPolicy.authorizationServer[0].cidr="} {
		if _, err := render(t, set); err == nil {
			t.Errorf("rendered with %s", set)
		}
	}
}
