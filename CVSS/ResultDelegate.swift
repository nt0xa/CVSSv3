//
//  ResultDelegate.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

protocol ResultDelegate {
    func updateScore(_ score: Float, animated: Bool)
    func updateSevirity(_ severity: String)
    func updateVector(_ vector: String)
}
