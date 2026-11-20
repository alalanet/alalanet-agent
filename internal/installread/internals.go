package installread

import "regexp"

// The reader's internals, exported only for the unit tests in internal/app. Those tests were written against these
// tables, constants and the second reader's state while the reader lived in that package; RT-1's second round moved the
// reader here unchanged and kept the tests unchanged (internal/app/installread_bridge_test.go maps the names back).
// Nothing else imports these names.

// The second reader's reasons (extra.go).
const (
	WhyOverride   = whyOverride
	WhyLoads      = whyLoads
	WhyDebug      = whyDebug
	WhyFlag       = whyFlag
	WhyCall       = whyCall
	WhyFromFile   = whyFromFile
	WhyFromOutput = whyFromOutput
	WhyJSON       = whyJSON
	WhyThrough    = whyThrough
	WhyGlued      = whyGlued
	WhyManySubst  = whyManySubst
	WhyHTTP       = whyHTTP
	WhyTmpDir     = whyTmpDir
	WhyUnknown    = whyUnknown
	WhyDeep       = whyDeep
)

// The registry sentences, the bounds and the markers of values the reader does not know.
const (
	SaidRegistry    = saidRegistry
	SaidConfig      = saidConfig
	RegistryHead    = registryHead
	RegistryTail    = registryTail
	ConfigHead      = configHead
	MaxSubst        = maxSubst
	MaxSubstNest    = maxSubstNest
	MaxHereWord     = maxHereWord
	MaxEvalGap      = maxEvalGap
	ExtraWork       = extraWork
	MaxExtraReasons = maxExtraReasons
	MaxPathValue    = maxPathValue
	TooLong         = tooLong
	UnknownValue    = unknownValue
)

// Lever is what an environment variable or a package manager's setting can move (env.go).
type Lever = lever

const (
	LvNone       = lvNone
	LvAny        = lvAny
	LvLoads      = lvLoads
	LvSource     = lvSource
	LvMirror     = lvMirror
	LvConfig     = lvConfig
	LvDirs       = lvDirs
	LvPath       = lvPath
	LvVenv       = lvVenv
	LvPython     = lvPython
	LvInterp     = lvInterp
	LvProgram    = lvProgram
	LvOff        = lvOff
	LvOn         = lvOn
	LvNodeOpts   = lvNodeOpts
	LvBunOpts    = lvBunOpts
	LvShellEnv   = lvShellEnv
	LvSSH        = lvSSH
	LvTLS        = lvTLS
	LvBreakpoint = lvBreakpoint
	LvWarnings   = lvWarnings
	LvKeyring    = lvKeyring
	LvKeyringUV  = lvKeyringUV
	LvStrategy   = lvStrategy
	LvUnverified = lvUnverified
	LvChecksum   = lvChecksum
	LvHome       = lvHome
)

// Tables.
var (
	EnvLevers        map[string]lever = envLevers
	PMKeys           map[string]lever = pmKeys
	PMCarriers       []string         = pmCarriers
	PMValueFlags     map[string]bool  = pmValueFlags
	PMVerbs          map[string]bool  = pmVerbs
	SSHOptions       map[string]bool  = sshOptions
	NodeMirrorHosts  map[string]bool  = nodeMirrorHosts
	NodeOwnReporters map[string]bool  = nodeOwnReporters
	PyRequest        *regexp.Regexp   = pyRequest
	VenvDir          *regexp.Regexp   = venvDir
)

// Helpers.
func AfterEval(b []byte) bool                         { return afterEval(b) }
func CmdVarHeld(ld string) bool                       { return cmdVarHeld(ld) }
func CompactKey(k string) string                      { return compactKey(k) }
func CwdFirst(v string) bool                          { return cwdFirst(v) }
func FalseLike(lv string) bool                        { return falseLike(lv) }
func HereWord(s string) string                        { return hereWord(s) }
func InitCommand(body string) bool                    { return initCommand(body) }
func JSONC(b []byte) []byte                           { return jsonc(b) }
func LaunchExtra(raw string) string                   { return launchExtra(raw) }
func LeverOf(k string) Lever                          { return leverOf(k) }
func LeverTail(tail string) bool                      { return leverTail(tail) }
func OwnOptionsEnd(cmd string, rest []string) int     { return ownOptionsEnd(cmd, rest) }
func ParamDefault(w string) string                    { return paramDefault(w) }
func PlainSSH(v string) bool                          { return plainSSH(v) }
func PMKeyLever(key string) Lever                     { return pmKeyLever(key) }
func PMPositional(rest []string, i int) int           { return pmPositional(rest, i) }
func PresentName(k string) bool                       { return presentName(k) }
func PSJSON(line string) string                       { return psJSON(line) }
func PSKey(k string) string                           { return psKey(k) }
func PSRef(s string) (name string, env bool, n int)   { return psRef(s) }
func RegistryDetail(r string) (kind, detail string)   { return registryDetail(r) }
func RiskyName(k string) bool                         { return riskyName(k) }
func Shown(v string) string                           { return shown(v) }
func SnakeUpper(k string) string                      { return snakeUpper(k) }
func SSHOptionOK(kv string) bool                      { return sshOptionOK(kv) }
func Unnest(line string) (pieces []string, over bool) { return unnest(line) }
func YarnSetting(k, v string) string                  { return yarnSetting(k, v) }

// ExtraParse is the second reader's state for one line, with what the tests read of it.
type ExtraParse = extraParse

func NewExtraParse() *ExtraParse { return newExtraParse() }

func (e *extraParse) Line(s string, depth int, through string) { e.line(s, depth, through) }
func (e *extraParse) Reasons() []string                        { return e.reasons() }
func (e *extraParse) Unread() []string                         { return e.unread }
func (e *extraParse) WorkLeft() *int                           { return &e.work }
func (e *extraParse) Assigned() map[string]string              { return e.assigned }
func (e *extraParse) PSValues() map[string]string              { return e.ps }
func (e *extraParse) AppendEnv(name, v string)                 { e.appendEnv(name, v) }
func (e *extraParse) PSEnv(k string, plus bool, raw string)    { e.psEnv(k, plus, raw) }
func (e *extraParse) PSValue(raw string) (string, bool)        { return e.psValue(raw) }
