package com.thtf.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 10:29
 * Version: v1.0
 * ========================
 */
@Data
public class SysRole implements Serializable {
    private static final long serialVersionUID = 7510551869226022669L;

    private Integer id;

    private String name;
}
