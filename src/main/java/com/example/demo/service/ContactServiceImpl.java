package com.example.demo.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.demo.domain.Contact;
import com.example.demo.repository.ContactRepository;

@Service
public class ContactServiceImpl implements ContactService {

	@Autowired
	private ContactRepository contactRepository;

	@Override
	public Iterable<Contact> findAll() {
		return contactRepository.findAll();
	}

	@Override
	public List<Contact> search(String q) {
		return contactRepository.findByNameContaining(q);
	}

	@Override
	public Contact findOne(int id) {
		return contactRepository.findById(id).get();
	}

	@Override
	public void save(Contact contact) {
		contactRepository.save(contact);
	}

	@Override
	public void delete(int id) {
		contactRepository.deleteById(id);
	}

}