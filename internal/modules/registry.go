package modules

var registry = make(map[string]Module)

func Register(m Module) {
	registry[m.Name()] = m
}

func Get(name string) Module {
	return registry[name]
}

func GetAll() []Module {
	modules := make([]Module, 0, len(registry))
	for _, m := range registry {
		modules = append(modules, m)
	}
	return modules
}

// InitModules registers all available modules
func InitModules() {
	Register(&Subfinder{})
	Register(&Naabu{})
	Register(&Nuclei{})
	Register(&Httpx{})
	Register(&Gowitness{})
	Register(&Katana{})
	Register(&Uncover{})
	Register(&Cvemap{})
	Register(&Urlfinder{})
	Register(&Interactsh{})
	Register(&Nmap{})
}
