package com.example.demo.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.demo.domain.Contact;
import com.example.demo.service.ContactService;

@Controller
@RequestMapping("/admin")
@Secured("ROLE_ADMIN")
public class ContactAdminController {

    @Autowired
    private ContactService contactService;

    @GetMapping("/contact")
    public String index(Model model) {
        model.addAttribute("contacts", contactService.findAll());
        return "admin/list";
    }
    @GetMapping("/contact/create")
    public String create(Model model) {
        model.addAttribute("contact", new Contact());
        return "admin/form";
    }
    @PostMapping("/contact/save")
    public String save(@Valid Contact contact, BindingResult result, RedirectAttributes redirect) {
        if (result.hasErrors()) {
            return "admin/form";
        }
        contactService.save(contact);
        redirect.addFlashAttribute("success", "Saved contact successfully!");
        return "redirect:/admin/contact";
    }
    @GetMapping("/contact/{id}/edit")
    public String edit(@PathVariable int id, Model model) {
        model.addAttribute("contact", contactService.findOne(id));
        return "admin/form";
    }
    @GetMapping("/contact/{id}/delete")
    public String delete(@PathVariable int id, RedirectAttributes redirect) {
        contactService.delete(id);
        redirect.addFlashAttribute("success", "Deleted contact successfully!");
        return "redirect:/admin/contact";
     }
    @GetMapping("/contact/search")
    public String search(@RequestParam("q") String q, Model model) {
        if (q.equals("")) {
            return "redirect:/admin/contact";
        }

        model.addAttribute("contacts", contactService.search(q));
        return "admin/list";
    }
}
