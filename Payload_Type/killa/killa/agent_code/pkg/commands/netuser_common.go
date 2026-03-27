package commands

type netUserArgs struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password"`
	Group    string `json:"group"`
	Comment  string `json:"comment"`
}
