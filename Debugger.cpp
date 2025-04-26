#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

struct ConfigDepurador {
    bool detallado = false;
    bool compilar_auto = true;
    bool mostrar_ensamblador = false;
    bool guardar_log = false;
    std::string compilador = "g++";
    std::string banderas_compilador = "-g -Wall -std=c++17";
    std::string archivo_log = "depurador.log";
    size_t max_pila = 10;
    bool pausa_en_main = true;
    bool ignorar_senales = false;
};

class Depurador {
private:
    std::string archivo_objetivo;
    std::string ejecutable;
    pid_t pid_hijo = 0;
    ConfigDepurador config;
    std::map<uint64_t, long> puntos_pausa;
    std::ofstream flujo_log;
    std::map<std::string, uint64_t> tabla_simbolos;
    std::set<std::string> variables_observadas;
    bool esta_corriendo = false;
    std::map<int, bool> senales_ignoradas;

    bool compilar_objetivo() {
        if (!config.compilar_auto) return true;
        std::string comando = config.compilador + " " + config.banderas_compilador + " " + 
                            archivo_objetivo + " -o " + ejecutable;
        if (config.detallado) {
            std::cout << "Compilando: " << comando << std::endl;
        }
        int resultado = system(comando.c_str());
        if (resultado != 0) {
            std::cerr << "¡Fallo la compilación!" << std::endl;
            return false;
        }
        return true;
    }

    void cargar_simbolos() {
        void* manejador = dlopen(ejecutable.c_str(), RTLD_LAZY);
        if (!manejador) {
            if (config.detallado) std::cerr << "No se pudo abrir el ejecutable para símbolos" << std::endl;
            return;
        }
        struct link_map* mapa;
        dlinfo(manejador, RTLD_DI_LINKMAP, &mapa);
        while (mapa) {
            if (config.detallado) {
                std::cout << "Cargando símbolos desde: " << mapa->l_name << std::endl;
            }
            mapa = mapa->l_next;
        }
        dlclose(manejador);
    }

    void registrar(const std::string& mensaje) {
        if (config.guardar_log && flujo_log.is_open()) {
            flujo_log << "[" << std::time(nullptr) << "] " << mensaje << std::endl;
        }
        if (config.detallado) {
            std::cout << "[REGISTRO] " << mensaje << std::endl;
        }
    }

    bool iniciar_hijo() {
        pid_t pid = fork();
        if (pid == 0) {
            personality(ADDR_NO_RANDOMIZE);
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
                std::cerr << "Fallo PTRACE_TRACEME" << std::endl;
                exit(1);
            }
            execl(ejecutable.c_str(), ejecutable.c_str(), nullptr);
            std::cerr << "Fallo al ejecutar " << ejecutable << std::endl;
            exit(1);
        } else if (pid > 0) {
            int estado;
            waitpid(pid, &estado, 0);
            if (WIFEXITED(estado)) {
                std::cerr << "El proceso hijo terminó prematuramente" << std::endl;
                return false;
            }
            ptrace(PTRACE_SETOPTIONS, pid, nullptr, 
                   PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC);
            pid_hijo = pid;
            esta_corriendo = true;
            if (config.pausa_en_main) {
                establecer_punto_pausa_main();
            }
            return true;
        }
        return false;
    }

    void establecer_punto_pausa_main() {
        uint64_t direccion_main = 0x400000;
        establecer_punto_pausa(direccion_main);
    }

    void establecer_punto_pausa(uint64_t direccion) {
        if (puntos_pausa.find(direccion) != puntos_pausa.end()) {
            registrar("Punto de pausa ya establecido en " + std::to_string(direccion));
            return;
        }
        long original = ptrace(PTRACE_PEEKTEXT, pid_hijo, direccion, nullptr);
        long trampa = (original & ~0xFF) | 0xCC;
        ptrace(PTRACE_POKETEXT, pid_hijo, direccion, trampa);
        puntos_pausa[direccion] = original;
        registrar("Punto de pausa establecido en 0x" + std::to_string(direccion));
    }

    void eliminar_punto_pausa(uint64_t direccion) {
        auto it = puntos_pausa.find(direccion);
        if (it == puntos_pausa.end()) return;
        ptrace(PTRACE_POKETEXT, pid_hijo, direccion, it->second);
        puntos_pausa.erase(it);
        registrar("Punto de pausa eliminado en 0x" + std::to_string(direccion));
    }

    void paso_instruccion() {
        if (!esta_corriendo) {
            std::cerr << "El programa no está corriendo" << std::endl;
            return;
        }
        ptrace(PTRACE_SINGLESTEP, pid_hijo, nullptr, nullptr);
        esperar_senal();
    }

    void continuar_ejecucion() {
        if (!esta_corriendo) {
            std::cerr << "El programa no está corriendo" << std::endl;
            return;
        }
        ptrace(PTRACE_CONT, pid_hijo, nullptr, nullptr);
        esperar_senal();
    }

    void esperar_senal() {
        int estado;
        waitpid(pid_hijo, &estado, 0);
        if (WIFEXITED(estado)) {
            registrar("Programa terminó con código " + std::to_string(WEXITSTATUS(estado)));
            esta_corriendo = false;
        } else if (WIFSTOPPED(estado)) {
            int senal = WSTOPSIG(estado);
            if (senal == SIGTRAP) {
                registrar("Punto de pausa o paso único alcanzado");
                struct user_regs_struct registros;
                ptrace(PTRACE_GETREGS, pid_hijo, nullptr, &registros);
                registros.rip -= 1;
                ptrace(PTRACE_SETREGS, pid_hijo, nullptr, &registros);
                inspeccionar_variables_observadas();
            } else if (!senales_ignoradas[senal] && !config.ignorar_senales) {
                registrar("Detenido por señal " + std::to_string(senal));
            } else {
                ptrace(PTRACE_CONT, pid_hijo, nullptr, nullptr);
            }
        }
    }

    void mostrar_pila() {
        struct user_regs_struct registros;
        ptrace(PTRACE_GETREGS, pid_hijo, nullptr, &registros);
        uint64_t rbp = registros.rbp;
        uint64_t rip = registros.rip;

        std::cout << "Rastro de pila:" << std::endl;
        for (size_t i = 0; i < config.max_pila && rbp != 0; ++i) {
            std::cout << "#" << i << " 0x" << std::hex << rip << std::dec;
            if (config.mostrar_ensamblador) {
                std::cout << " [ensamblador no implementado]";
            }
            std::cout << std::endl;
            rip = ptrace(PTRACE_PEEKTEXT, pid_hijo, rbp + 8, nullptr);
            rbp = ptrace(PTRACE_PEEKTEXT, pid_hijo, rbp, nullptr);
        }
    }

    void inspeccionar_variable(const std::string& nombre_var) {
        std::cout << "Inspeccionando " << nombre_var << ": [valor simulado]" << std::endl;
        registrar("Inspección de variable: " + nombre_var);
    }

    void inspeccionar_variables_observadas() {
        for (const auto& var : variables_observadas) {
            inspeccionar_variable(var);
        }
    }

    void agregar_variable_observada(const std::string& nombre_var) {
        variables_observadas.insert(nombre_var);
        registrar("Variable observada agregada: " + nombre_var);
    }

    void eliminar_variable_observada(const std::string& nombre_var) {
        variables_observadas.erase(nombre_var);
        registrar("Variable observada eliminada: " + nombre_var);
    }

public:
    Depurador(const std::string& archivo, const ConfigDepurador& cfg) 
        : archivo_objetivo(archivo), config(cfg) {
        ejecutable = fs::path(archivo).stem().string() + ".out";
        if (config.guardar_log) {
            flujo_log.open(config.archivo_log, std::ios::app);
        }
        senales_ignoradas[SIGINT] = false;
        senales_ignoradas[SIGTERM] = false;
    }

    ~Depurador() {
        if (flujo_log.is_open()) {
            flujo_log.close();
        }
        if (esta_corriendo) {
            kill(pid_hijo, SIGKILL);
        }
    }

    bool iniciar() {
        if (!compilar_objetivo()) return false;
        cargar_simbolos();
        if (!iniciar_hijo()) return false;
        registrar("Depurador iniciado para " + ejecutable);
        return true;
    }

    void ejecutar_interactivo() {
        std::string comando;
        std::cout << "(depurador) ";
        while (std::getline(std::cin, comando)) {
            std::istringstream iss(comando);
            std::string cmd;
            iss >> cmd;

            if (cmd == "ejecutar" || cmd == "e") {
                if (!esta_corriendo) {
                    if (!iniciar()) {
                        std::cerr << "Fallo al iniciar el depurador" << std::endl;
                    }
                } else {
                    continuar_ejecucion();
                }
            } else if (cmd == "pausa" || cmd == "p") {
                uint64_t direccion;
                iss >> std::hex >> direccion;
                establecer_punto_pausa(direccion);
            } else if (cmd == "eliminar" || cmd == "el") {
                uint64_t direccion;
                iss >> std::hex >> direccion;
                eliminar_punto_pausa(direccion);
            } else if (cmd == "paso" || cmd == "s") {
                paso_instruccion();
            } else if (cmd == "continuar" || cmd == "c") {
                continuar_ejecucion();
            } else if (cmd == "pila" || cmd == "rp") {
                mostrar_pila();
            } else if (cmd == "inspeccionar" || cmd == "i") {
                std::string nombre_var;
                iss >> nombre_var;
                inspeccionar_variable(nombre_var);
            } else if (cmd == "observar" || cmd == "o") {
                std::string nombre_var;
                iss >> nombre_var;
                agregar_variable_observada(nombre_var);
            } else if (cmd == "noobservar" || cmd == "no") {
                std::string nombre_var;
                iss >> nombre_var;
                eliminar_variable_observada(nombre_var);
            } else if (cmd == "configurar") {
                std::string clave, valor;
                iss >> clave >> valor;
                if (clave == "detallado") config.detallado = (valor == "verdadero");
                else if (clave == "mostrar_ensamblador") config.mostrar_ensamblador = (valor == "verdadero");
                else if (clave == "max_pila") config.max_pila = std::stoul(valor);
                else if (clave == "ignorar_senales") config.ignorar_senales = (valor == "verdadero");
                else std::cerr << "Clave de configuración desconocida" << std::endl;
            } else if (cmd == "salir" || cmd == "s") {
                break;
            } else {
                std::cout << "Comandos:\n"
                          << "  ejecutar (e) - Iniciar o continuar ejecución\n"
                          << "  pausa (p) <dir> - Establecer punto de pausa\n"
                          << "  eliminar (el) <dir> - Eliminar punto de pausa\n"
                          << "  paso (s) - Avanzar una instrucción\n"
                          << "  continuar (c) - Continuar ejecución\n"
                          << "  pila (rp) - Mostrar rastro de pila\n"
                          << "  inspeccionar (i) <var> - Inspeccionar variable\n"
                          << "  observar (o) <var> - Observar variable\n"
                          << "  noobservar (no) <var> - Dejar de observar variable\n"
                          << "  configurar <clave> <valor> - Ajustar configuración\n"
                          << "  salir (s) - Salir\n";
            }
            if (esta_corriendo) {
                std::cout << "(depurador) ";
            } else {
                std::cout << "(depurador, detenido) ";
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Uso: " << argv[0] << " <archivo_fuente> [opciones]\n"
                  << "Opciones:\n"
                  << "  --detallado          Habilitar registros detallados\n"
                  << "  --no-compilar       Deshabilitar compilación automática\n"
                  << "  --mostrar-ensamblador Mostrar ensamblador en pila\n"
                  << "  --archivo-log <archivo> Guardar log en archivo\n"
                  << "  --compilador <cmd>  Establecer compilador (predeterminado: g++)\Reached maximum artifact size limit of 16384 characters.