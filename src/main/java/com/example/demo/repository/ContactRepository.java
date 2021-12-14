package com.example.demo.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.domain.Contact;

@Repository
public interface ContactRepository extends CrudRepository<Contact, Integer> {
	List<Contact> findByNameContaining(String q);
}
