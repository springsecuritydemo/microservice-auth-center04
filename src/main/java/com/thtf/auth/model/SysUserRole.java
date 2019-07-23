package com.thtf.auth.model;

import lombok.Data;

import java.io.Serializable;

/**
 * ========================
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/7/23 10:30
 * Version: v1.0
 * ========================
 */
@Data
public class SysUserRole implements Serializable{
    private static final long serialVersionUID = -3256750757278740295L;

    private Integer userId;

    private Integer roleId;
}
