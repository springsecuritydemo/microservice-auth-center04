package com.thtf.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 10:24
 * Version: v1.0
 * ========================
 */
@Data
public class SysUser implements Serializable{
    private static final long serialVersionUID = -2836223054703407171L;

    private Integer id;

    private String name;

    private String password;
}
