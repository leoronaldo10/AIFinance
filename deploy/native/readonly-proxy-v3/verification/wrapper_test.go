package offlineverify
import (
 "encoding/json"
 "os"
 "testing"
 "offlineverify/shlex"
)
func TestFixedWrapper(t *testing.T) {
 data, err := os.ReadFile("fixture.json"); if err != nil { t.Fatal(err) }
 var f struct { Line string `json:"command_line"`; Command string `json:"command"` }
 if err := json.Unmarshal(data, &f); err != nil { t.Fatal(err) }
 if len(f.Line) != 499 || len(f.Line)>512 { t.Fatal("length mismatch") }
 args, err := shlex.Split(f.Line)
 if err != nil { t.Fatal(err) }
 if len(args)!=3 || args[0]!="/bin/sh" || args[1]!="-c" || args[2]!=f.Command { t.Fatal("argv mismatch") }
 old, err := shlex.Split(f.Command)
 if err != nil || len(old)<=3 || old[0]!="test" { t.Fatal("old direct-exec mismatch") }
}
func TestMalformedWrapper(t *testing.T) {
 for _, line := range []string{"/bin/sh -c 'unterminated", "/bin/sh -c \"unterminated"} {
  if _, err := shlex.Split(line); err == nil { t.Fatal("unterminated quote accepted") }
 }
}
