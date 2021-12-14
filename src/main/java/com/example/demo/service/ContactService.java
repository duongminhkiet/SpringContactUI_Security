package com.example.demo.service;

import java.util.List;

import com.example.demo.domain.Contact;

public interface ContactService {
	Iterable<Contact> findAll();

    List<Contact> search(String q);

    Contact findOne(int id);

    void save(Contact contact);

    void delete(int id);
}
