//
//  ResultDelegate.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

protocol ResultDelegate {
    func update(score: Float, severity: String, vector: String, animated: Bool)
}
