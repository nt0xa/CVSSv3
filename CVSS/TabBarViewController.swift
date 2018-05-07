//
//  TabBarViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class TabBarViewController: UITabBarController, UITabBarControllerDelegate {
    let cvss = CVSS()
    var previousSelectedItemIndex: Int? = nil
    
    override func viewDidLoad() {
        super.viewDidLoad()
        becomeFirstResponder()
        self.delegate = self
    }
    
    override var canBecomeFirstResponder: Bool {
        get {
            return true
        }
    }
    
    override func motionEnded(_ motion: UIEventSubtype, with event: UIEvent?) {
        if motion == .motionShake {
            cvss.resetToDefaults()
            
            customizableViewControllers?.forEach({ vc in
                if vc.isViewLoaded {
                    let formDelegate = vc as! FormDelegate
                    formDelegate.syncForm()
                    formDelegate.updateResult()
                }
            })
        }
    }
    
    func tabBarController(_ tabBarController: UITabBarController, shouldSelect viewController: UIViewController) -> Bool {
        previousSelectedItemIndex = tabBarController.selectedIndex
        return true
    }
}
