package org.example.taskmanager11.controllers;

import jakarta.servlet.http.HttpSession;
import org.example.taskmanager11.model.Client;
import org.example.taskmanager11.repo.ClientRepository;
import org.example.taskmanager11.services.ClientService;
import org.example.taskmanager11.utils.Utils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ClientController {

    private final ClientService clientService;
    private final ClientRepository clientRepository;

    public ClientController(ClientService clientService, ClientRepository clientRepository) {
        this.clientService = clientService;
        this.clientRepository = clientRepository;
    }

    @GetMapping("register")
    public String register() {
        return "register";
    }

    @GetMapping("login")
    public String login() {
        return "login";
    }

    @PostMapping("register")
    public String register(@RequestParam String login,
                           @RequestParam String password) {
        String salt = Utils.generateRandomString(10);
        String hash = Utils.passwordHash(salt, password);

        clientService.addClient(login, salt, hash);
        return "redirect:/login";
    }

    @PostMapping("login")
    public String login(@RequestParam String login,
                        @RequestParam String password,
                        HttpSession session) {
        if (clientService.checkClient(login, password)) {
            session.setAttribute("login", login);
            return "redirect:/";
        } else
            return "redirect:/login";
    }

    @GetMapping("logout")
    public String logout(HttpSession session) {
        session.removeAttribute("login");
        return "redirect:/";
    }

    @GetMapping("/change")
    public String showChangePasswordForm() {
        return "change";
    }

    @PostMapping("/change")
    public String handlePasswordChange(
            @RequestParam String login,
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword) {
        Client client = clientRepository.findByLogin(login);
        String salt = client.getSalt();
        String currentHash = Utils.passwordHash(salt, currentPassword);
        if(!(newPassword.equals(confirmPassword))) {
            throw new RuntimeException("Passwords do not match");
        }
        if(client.getPassword().equals(currentHash)) {
            String saltNew = Utils.generateRandomString(10);
            String newHash = Utils.passwordHash(saltNew, newPassword);
            clientService.updateClient(login, saltNew, newHash);
        }
        else {
            throw new RuntimeException("Invalid current password");
        }

        return "login";
    }
}
